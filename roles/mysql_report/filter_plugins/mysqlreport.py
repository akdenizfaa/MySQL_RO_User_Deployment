# -*- coding: utf-8 -*-
"""Sonuç raporu: her host'ta ne yapıldı / neden yapılamadı.

Aynı sonucu alan host'lar tek satırda gruplanır (kümülatif). Ayrıntılı veri
(hesap, ifade, native audit listeleri) AAP job artifact'ına yazılır.
"""
from __future__ import annotations

import os
import re
import sys

_UC = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                                    "mysql_user_check", "filter_plugins"))
if _UC not in sys.path:
    sys.path.insert(0, _UC)
import mysqluser  # noqa: E402  (yetki seti -> istenen yetkiler)

# ----------------------------------------------------------------------------- etiketler
CATEGORIES = [
    # anahtar, başlık, job'ı FAILED yapar mı
    ("ERROR", "HATA - bağlanılamadı / işlem hata verdi", True),
    ("BLOCKED", "YAPILAMADI - aksiyon gerekiyor", True),
    ("DONE", "DEĞİŞİKLİK YAPILDI", False),
    ("PLANNED", "PLANLANAN (check modu - uygulanmadı)", False),
    ("NEEDED", "İŞLEM GEREKİYOR (Faz 4 ile uygulanır)", False),
    ("REPORT_ONLY", "ŞİFRE FARKLI - 'report' seçildiği için değiştirilmedi", False),
    ("REPLICA", "REPLİKA / SECONDARY - yazılmadı (beklenen)", False),
    ("OK", "UYGUN - işlem gerekmedi", False),
    ("CONNECTED", "BAĞLANTI BAŞARILI", False),
    ("SKIPPED", "ATLANDI (envanter)", False),
]
FAIL_CATEGORIES = {k for k, _, f in CATEGORIES if f}
SHORT = {"ERROR": "hata", "BLOCKED": "yapılamadı", "DONE": "değişiklik yapıldı",
         "PLANNED": "planlandı", "NEEDED": "işlem gerekiyor", "REPORT_ONLY": "şifre farklı",
         "REPLICA": "replika", "OK": "uygun", "CONNECTED": "bağlantı OK", "SKIPPED": "atlandı"}

CONN_TEXT = {
    "SSH_UNREACHABLE": "SSH bağlantısı kurulamadı",
    "SSH_AUTH_FAIL": "SSH kimlik doğrulaması başarısız",
    "HOST_ERROR": "Sunucuda komut çalıştırılamadı",
    "MYSQL_CLIENT_NOT_FOUND": "mysql client bulunamadı",
    "MYSQL_AUTH_FAIL": "MySQL admin girişi reddedildi",
    "MYSQL_UNREACHABLE": "MySQL servisine ulaşılamadı",
    "MYSQL_ERROR": "MySQL hatası",
}
ACTION_TEXT = {  # kind -> (yapıldı, yapılacak)
    "CREATE_USER": ("oluşturuldu", "oluşturulacak"),
    "ALTER_USER_PASSWORD": ("şifre güncellendi", "şifre güncellenecek"),
    "ALTER_USER_PLUGIN": ("caching_sha2_password'e dönüştürüldü", "caching_sha2_password'e dönüştürülecek"),
}

_GRANT_PRIVS = re.compile(r"^GRANT (?P<privs>.+?) ON ")
MAX_HOSTS_PER_LINE = 6
MAX_DETAIL = 220


# ----------------------------------------------------------------------------- yardımcılar
def _hv(hostvars, name):
    return hostvars.get(name, {}) if hasattr(hostvars, "get") else hostvars[name]


def _fact(hv, key, default=None):
    """set_fact (vars) veya action plugin (ansible_facts) ile gelen değeri oku."""
    val = hv.get(key)
    if val is None:
        val = (hv.get("ansible_facts") or {}).get(key)
    return default if val is None else val


def _short(text, limit=MAX_DETAIL):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _grant_text(template, desired, done):
    if template.startswith("GRANT USAGE") and " WITH GRANT OPTION" in template:
        return "GRANT OPTION eklendi" if done else "GRANT OPTION eklenecek"
    m = _GRANT_PRIVS.match(template)
    privs = [p.strip() for p in m.group("privs").split(",")] if m else []
    if desired and privs == desired.get("privileges"):
        txt = "yetkiler verildi" if done else "yetkiler verilecek"
    else:
        txt = ("eksik yetkiler verildi: " if done else "eksik yetkiler verilecek: ") + ", ".join(privs)
    if " WITH GRANT OPTION" in template:
        txt += " (+GRANT OPTION)"
    return txt


def _actions_text(statements, desired, done):
    out = []
    for st in statements:
        if st["kind"] == "GRANT":
            out.append(_grant_text(st["template"], desired, done))
        else:
            out.append(ACTION_TEXT.get(st["kind"], (st["kind"], st["kind"]))[0 if done else 1])
    return ", ".join(out)


def _account_msgs(accounts, desired, done):
    parts = []
    for acc in accounts:
        sts = [s for s in acc.get("statements", []) if not s.get("blocked")]
        if sts:
            parts.append("%s: %s" % (acc["account"], _actions_text(sts, desired, done)))
    return parts


def _verify_text(post_by, accounts):
    """Uygulama sonrası doğrulama özeti."""
    bad = []
    for acc in accounts:
        sts = [s for s in acc.get("statements", []) if not s.get("blocked")]
        if not sts:
            continue
        p = post_by.get(acc["account"])
        if not p:
            bad.append("%s doğrulanamadı" % acc["account"])
        elif p["status"] == "NOT_EXISTS" or p.get("missing_privileges") or (
                p["status"] == "EXISTS_PASSWORD_DIFFERENT"
                and any(s["kind"] == "ALTER_USER_PASSWORD" for s in sts)):
            bad.append("%s: %s%s" % (acc["account"], p["status"],
                                     " (eksik: %s)" % ", ".join(p["missing_privileges"])
                                     if p.get("missing_privileges") else ""))
    return "doğrulama: " + ("; ".join(bad) if bad else "OK")


# ----------------------------------------------------------------------------- host sınıflandırma
def _classify(hv, phase, desired):
    """(kategori, mesaj) döndür."""
    c = _fact(hv, "mysqlconn", {}) or {}
    err = _fact(hv, "mysqlhost_error") or {}
    if not c:
        return "ERROR", "Sonuç üretilemedi (host görevi çalışmadı; job log'una bakın)"
    if c.get("status") != "OK":
        return "ERROR", "%s: %s" % (CONN_TEXT.get(c.get("status"), c.get("status")), _short(c.get("detail")))

    if phase == "connect":
        notes = [x for x in str(c.get("detail") or "").split("; ") if x]
        msg = "MySQL %s (%s)" % (c.get("version", "?"), c.get("method", "?"))
        return "CONNECTED", msg + (" - " + "; ".join(notes) if notes else "")

    before = _fact(hv, "mysqluser_before") or _fact(hv, "mysqluser", {}) or {}
    if before.get("status") != "CHECKED":
        return "ERROR", "Hesap bilgileri okunamadı: %s" % _short(before.get("detail") or err.get("detail"))
    accounts = [a for a in before.get("accounts", []) if a.get("status") != "EXTRA_ACCOUNT"]
    blocked = [s for a in accounts for s in a.get("statements", []) if s.get("blocked")]
    pending = [s for a in accounts for s in a.get("statements", []) if not s.get("blocked")]
    report_only = [a["account"] for a in accounts if "ŞİFRE_FARKLI_SADECE_RAPOR" in a.get("flags", [])]
    pol = before.get("password_policy") or {}
    pol_txt = "Şifre politikası (%s): %s" % (pol.get("policy", "?"), "; ".join(pol.get("reasons", [])))
    ro_txt = (" | şifre farklı, değiştirilmedi (report): " + ", ".join(report_only)) if report_only else ""

    if phase == "check":
        if blocked:
            return "BLOCKED", pol_txt
        if pending:
            msg = " | ".join(_account_msgs(accounts, desired, done=False))
            if c.get("read_only"):
                return "REPLICA", "read_only: %s (primary'den replike olur)" % msg
            return "NEEDED", msg + ro_txt
        if report_only:
            return "REPORT_ONLY", ", ".join(report_only)
        return "OK", "Hesap, şifre ve yetkiler uygun"

    # ---- deploy
    ap = _fact(hv, "mysqlapply", {}) or {}
    st = ap.get("status", "")
    if err and st not in ("PARTIAL", "FAILED", "UNKNOWN"):
        # uygulama başarılı ama doğrulama sırasında bağlantı koptu vb.
        if st == "APPLIED":
            return "DONE", " | ".join(_account_msgs(accounts, desired, done=True)) + "; " + _short(ap.get("detail"))
    if st == "APPLIED":
        post = _fact(hv, "mysqluser", {}) if _fact(hv, "mysqluser_post_checked") else {}
        post_by = {a["account"]: a for a in (post or {}).get("accounts", [])}
        msg = " | ".join(_account_msgs(accounts, desired, done=True)) + "; " + _verify_text(post_by, accounts)
        if blocked:
            return "BLOCKED", msg + " | YAPILAMAYAN: " + pol_txt
        return "DONE", msg + ro_txt
    if st in ("PARTIAL", "FAILED"):
        ok = ["%s %s" % (r["account"], r["kind"]) for r in ap.get("results", []) if r["result"] == "APPLIED"]
        return "ERROR", "SQL hatası: %s%s" % (_short(ap.get("detail")),
                                              " | uygulananlar: " + ", ".join(ok) if ok else "")
    if st == "UNKNOWN":
        return "ERROR", "%s | hangi ifadelerin çalıştığı belirsiz; user_check.yml ile kontrol edin" % _short(ap.get("detail"))
    if st == "BLOCKED_PASSWORD_POLICY" or (blocked and st in ("CHECK_MODE", "SKIPPED_READ_ONLY")):
        return "BLOCKED", pol_txt
    if st == "SKIPPED_PORT_MISMATCH":
        return "BLOCKED", _short(ap.get("detail"))
    if st == "SKIPPED_READ_ONLY":
        return "REPLICA", "read_only: %s (primary'den replike olur)" % " | ".join(
            _account_msgs(accounts, desired, done=False))
    if st == "CHECK_MODE":
        return "PLANNED", " | ".join(_account_msgs(accounts, desired, done=False)) + ro_txt
    if st == "SKIPPED_CHECK_ERROR":
        return "ERROR", "Hesap bilgileri okunamadı: %s" % _short(ap.get("detail"))
    if report_only:
        return "REPORT_ONLY", ", ".join(report_only)
    return "OK", "Hesap, şifre ve yetkiler uygun"


# ----------------------------------------------------------------------------- kümülatif notlar
_CLUSTER_RE = ("mysql_innodb_cluster_", "mysql_router", "mysqlrouter", "mysql_innodb_rs_", "mysql_innodb_cs_")


def _native_category(account):
    user = account.rsplit("@", 1)[0].lower()
    if user.startswith(_CLUSTER_RE):
        return ("CLUSTER_ROUTER_İÇ_HESAP",
                "InnoDB Cluster/Router yönetir; MySQL Shell/Router yeniden yapılandırmasıyla dönüştürülmeli")
    if user == "root":
        return "ROOT", "Planlı bakımda dönüştürülmeli; otomasyon bağlantısı etkilenebilir"
    return "UYGULAMA_SERVİS", "Client kütüphanesi caching_sha2_password desteği doğrulanıp dönüştürülmeli"


def _notes(hosts, hostvars, phase):
    groups, native = {}, []

    def add(key, host):
        lst = groups.setdefault(key, [])
        if host not in lst:
            lst.append(host)

    for name in hosts:
        hv = _hv(hostvars, name)
        c = _fact(hv, "mysqlconn", {}) or {}
        if c.get("status") == "OK" and c.get("method") == "socket" and phase != "connect":
            add("TCP ile bağlanılamadı, socket kullanıldı", name)
        u = _fact(hv, "mysqluser", {}) or {}
        if u.get("status") != "CHECKED":
            u = _fact(hv, "mysqluser_before", {}) or {}
        for a in u.get("accounts", []):
            f = a.get("flags", [])
            if a.get("status") == "EXTRA_ACCOUNT":
                add("Survey'de olmayan ek hesap (%s)" % a["account"], name)
            if "FAZLA_YETKİ" in f:
                extra = list(a.get("extra_privileges", []))
                if a.get("other_grants"):
                    extra.append("%d şema/tablo grant" % len(a["other_grants"]))
                add("Fazla yetki, REVOKE edilmedi (%s: %s)" % (a["account"], ", ".join(extra)), name)
            if "MEVCUT_GRANT_OPTION" in f:
                add("İstenmediği halde GRANT OPTION var (%s)" % a["account"], name)
            if "ACCOUNT_LOCKED" in f:
                add("Hesap kilitli (%s)" % a["account"], name)
            if "PASSWORD_EXPIRED" in f:
                add("Şifre süresi dolmuş (%s)" % a["account"], name)
            if "NATIVE_DÖNÜŞÜM_İÇİN_UPDATE_GEREKİR" in f:
                add("Hedef hesap hâlâ mysql_native_password; dönüşüm için 'update' seçin (%s)" % a["account"], name)
        for acc in u.get("native_password_accounts", []):
            cat, issue = _native_category(acc)
            native.append({"server": name, "environment": hv.get("mysql_env", ""),
                           "account": acc, "category": cat, "issue": issue})
        for x in (u.get("password_policy") or {}).get("unchecked", []):
            add("Yerelde kontrol edilemedi: %s" % x, name)
    return groups, native


def _host_lines(hosts, indent="      "):
    return [indent + ", ".join(hosts[i:i + MAX_HOSTS_PER_LINE])
            for i in range(0, len(hosts), MAX_HOSTS_PER_LINE)]


def _group_lines(items, single_fmt, multi_fmt):
    out = []
    for msg, hs in sorted(items, key=lambda kv: (-len(kv[1]), kv[0])):
        if len(hs) <= 2:
            out.append(single_fmt % {"h": ", ".join(hs), "m": msg})
        else:
            out.append(multi_fmt % {"m": msg, "n": len(hs)})
            out.extend(_host_lines(hs))
    return out


# ----------------------------------------------------------------------------- ana filtre
def mysqlreport_build(hostnames, hostvars, skipped=None, ctx=None):
    """Kullanıcı dostu rapor.

    ctx: {phase: connect|check|deploy, check_mode, environments, inputs, title}
    Dönen: {lines, summary, hosts, apply, native}
    """
    ctx = ctx or {}
    phase = ctx.get("phase", "connect")
    inputs = ctx.get("inputs") or {}
    desired = mysqluser.mysqluser_desired(inputs["privilege_sets"]) if inputs.get("privilege_sets") else {}
    hosts = sorted(hostnames or [])
    per_host, buckets = [], {}
    for name in hosts:
        hv = _hv(hostvars, name)
        cat, msg = _classify(hv, phase, desired)
        per_host.append({"server": name, "environment": hv.get("mysql_env", ""),
                         "ip": hv.get("ansible_host", ""), "category": cat, "message": msg})
        buckets.setdefault(cat, {}).setdefault(msg, []).append(name)
    for s in skipped or []:
        buckets.setdefault("SKIPPED", {}).setdefault(s.get("reason", ""), []).append(s.get("name", ""))
        per_host.append({"server": s.get("name", ""), "environment": s.get("environment", ""),
                         "ip": "", "category": "SKIPPED", "message": s.get("reason", "")})

    counts = {k: sum(len(v) for v in buckets.get(k, {}).values()) for k, _, _ in CATEGORIES}
    mode = "CHECK" if ctx.get("check_mode") else "RUN"
    bar = "=" * 78

    title = ctx.get("title", "MySQL raporu") + (" [%s]" % mode if phase == "deploy" else "")
    lines = [bar, title, bar, "Ortam        : %s" % ", ".join(ctx.get("environments") or [])]
    if inputs:
        lines.append("Kullanıcı    : %s  (host: %s)" % (inputs.get("user"), ", ".join(inputs.get("hosts", []))))
        lines.append("Yetki seti   : %s%s" % (", ".join(inputs.get("privilege_sets", [])),
                                             " (+GRANT OPTION)" if desired.get("grant_option") else ""))
        lines.append("Şifre farklı : %s" % inputs.get("mismatch_action"))
    lines.append("Sunucu       : %d hedef, %d envanterde atlandı" % (len(hosts), counts["SKIPPED"]))
    lines.append("Sonuç        : " + ", ".join("%d %s" % (counts[k], SHORT[k])
                                              for k, _, _ in CATEGORIES if counts[k]))

    for key, head, _ in CATEGORIES:
        if not buckets.get(key):
            continue
        lines += ["", "[%s] %d sunucu" % (head, counts[key])]
        lines += _group_lines(buckets[key].items(), "  - %(h)s: %(m)s", "  - %(m)s (%(n)d sunucu):")

    notes, native = _notes(hosts, hostvars, phase)
    if notes or native:
        lines += ["", "[DİKKAT]"]
        lines += _group_lines(notes.items(), "  - %(m)s: %(h)s", "  - %(m)s (%(n)d sunucu):")
        if native:
            by_cat = {}
            for n in native:
                by_cat.setdefault(n["category"], {"acc": 0, "srv": set()})
                by_cat[n["category"]]["acc"] += 1
                by_cat[n["category"]]["srv"].add(n["server"])
            lines.append("  - mysql_native_password audit: %d hesap / %d sunucu"
                         % (len(native), len({n["server"] for n in native})))
            for cat, v in sorted(by_cat.items()):
                lines.append("      %s: %d hesap, %d sunucu" % (cat, v["acc"], len(v["srv"])))
            lines.append("      (hesap listesi: job artifact 'mysqlreport_native')")
    lines.append(bar)

    apply_rows = []
    for name in hosts:
        ap = _fact(_hv(hostvars, name), "mysqlapply", {}) or {}
        for r in ap.get("results", []):
            planned = r["result"] == "PLANNED"
            apply_rows.append({"server": name, "account": r["account"], "statement": r["masked"],
                               "result": ap.get("status", "PLANNED") if planned else r["result"],
                               "error": (ap.get("detail") if planned else r.get("error")) or ""})

    failed = sorted({h["server"] for h in per_host if h["category"] in FAIL_CATEGORIES})
    summary = {"title": ctx.get("title"), "mode": mode, "phase": phase,
               "environments": ctx.get("environments") or [],
               "counts": {k: counts[k] for k, _, _ in CATEGORIES if counts[k]},
               "failed_servers": failed, "native_password_account_count": len(native)}
    return {"lines": lines, "summary": summary, "hosts": per_host, "apply": apply_rows, "native": native}


def mysqlreport_count_by(rows, key):
    counts = {}
    for r in rows or []:
        counts[r[key]] = counts.get(r[key], 0) + 1
    return dict(sorted(counts.items()))


class FilterModule(object):
    def filters(self):
        return {
            "mysqlreport_build": mysqlreport_build,
            "mysqlreport_count_by": mysqlreport_count_by,
        }
