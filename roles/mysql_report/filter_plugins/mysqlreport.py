# -*- coding: utf-8 -*-
"""Host bazlı sonuçları rapor satırlarına ve metin tabloya çevirir."""
from __future__ import annotations


def mysqlreport_rows(hostnames, hostvars, skipped=None, result_var="mysqlconn"):
    """Her hedef için bir satır + envanterde elenenler (SKIPPED).

    Hedef host'ta result_var yoksa (beklenmeyen task hatası) ERROR yazılır.
    """
    rows = []
    for name in sorted(hostnames or []):
        hv = hostvars.get(name, {}) if hasattr(hostvars, "get") else hostvars[name]
        res = hv.get(result_var) or {}
        rows.append({
            "server": name,
            "environment": hv.get("mysql_env", ""),
            "ip": hv.get("ansible_host", ""),
            "port": hv.get("mysql_port", ""),
            "status": res.get("status") or "ERROR",
            "method": res.get("method", ""),
            "version": res.get("version", ""),
            "detail": res.get("detail") if res else "Sonuç üretilemedi; job log'unda bu host'un hatasına bakın",
        })
    for s in skipped or []:
        rows.append({
            "server": s.get("name", ""), "environment": s.get("environment", ""),
            "ip": "", "port": "", "status": "SKIPPED", "method": "", "version": "",
            "detail": s.get("reason", ""),
        })
    return rows


def _hv(hostvars, name):
    return hostvars.get(name, {}) if hasattr(hostvars, "get") else hostvars[name]


def _post_text(acc):
    if not acc:
        return ""
    txt = acc["status"]
    if acc.get("plugin"):
        txt += " [%s]" % acc["plugin"]
    if acc.get("missing_privileges"):
        txt += " (eksik: %s)" % ", ".join(acc["missing_privileges"])
    return txt


def mysqlreport_account_rows(hostnames, hostvars, result_var="mysqluser"):
    """Sunucu x hesap satırları.

    Faz 4'te mysqluser_before (uygulama öncesi) ve mysqluser (doğrulama sonrası)
    birlikte gösterilir; Faz 3'te yalnızca mysqluser vardır.
    """
    rows = []
    for name in sorted(hostnames or []):
        hv = _hv(hostvars, name)
        before = hv.get("mysqluser_before") or hv.get(result_var) or {}
        after = hv.get(result_var) if hv.get("mysqluser_post_checked") else None
        apply = hv.get("mysqlapply") or {}
        base = {"server": name, "environment": hv.get("mysql_env", "")}
        if before.get("status") != "CHECKED":
            rows.append(dict(base, account="-", status=before.get("status") or "ERROR",
                             plugin="", password="", missing="", extra="", flags="",
                             planned=before.get("detail", "") if before else "Sonuç üretilemedi",
                             apply=apply.get("status", ""), post=""))
            continue
        after_by = {a["account"]: a for a in (after or {}).get("accounts", [])} if after else {}
        for a in before.get("accounts", []):
            res = [r["result"] for r in apply.get("results", []) if r["account"] == a["account"]]
            if not a.get("statements"):
                apply_txt = "-"
            elif "SKIPPED_PASSWORD_POLICY" in res and "FAILED" not in res:
                apply_txt = "BLOCKED_PASSWORD_POLICY"
            elif apply.get("status") in ("CHECK_MODE", "SKIPPED_READ_ONLY", "SKIPPED_PORT_MISMATCH",
                                         "SKIPPED_CONNECTION", "SKIPPED_CHECK_ERROR"):
                apply_txt = apply["status"]
            else:
                apply_txt = "FAILED" if "FAILED" in res else ("APPLIED" if res and set(res) == {"APPLIED"} else ",".join(sorted(set(res))) or "-")
            extra = list(a.get("extra_privileges", []))
            if a.get("other_grants"):
                extra.append("+%d şema/tablo grant" % len(a["other_grants"]))
            rows.append(dict(base, account=a["account"], status=a["status"], plugin=a["plugin"],
                             password=a["password"], missing=", ".join(a["missing_privileges"]),
                             extra=", ".join(extra), flags=", ".join(a["flags"]),
                             planned="; ".join(a["planned_actions"]) or "-",
                             apply=apply_txt, post=_post_text(after_by.get(a["account"]))))
    return rows


def mysqlreport_apply_rows(hostnames, hostvars):
    """Faz 4: ifade bazlı uygulama sonucu (SQL maskeli)."""
    rows = []
    for name in sorted(hostnames or []):
        hv = _hv(hostvars, name)
        ap = hv.get("mysqlapply") or {}
        for r in ap.get("results", []):
            result = r["result"]
            error = r.get("error", "")
            if result == "PLANNED":
                result = ap.get("status", "PLANNED")
                error = ap.get("detail", "")
            rows.append({"server": name, "environment": hv.get("mysql_env", ""),
                         "account": r["account"], "statement": r["masked"],
                         "result": result, "error": error})
    return rows


_CLUSTER_RE = ("mysql_innodb_cluster_", "mysql_router", "mysqlrouter", "mysql_innodb_rs_", "mysql_innodb_cs_")


def _native_category(account):
    user = account.rsplit("@", 1)[0].lower()
    if user.startswith(_CLUSTER_RE):
        return ("CLUSTER_ROUTER_İÇ_HESAP",
                "InnoDB Cluster/Router yönetir; MySQL Shell/Router yeniden yapılandırmasıyla dönüştürülmeli")
    if user == "root":
        return "ROOT", "Planlı bakımda dönüştürülmeli; otomasyon bağlantısı etkilenebilir"
    return "UYGULAMA_SERVİS", "Client kütüphanesi caching_sha2_password desteği doğrulanıp dönüştürülmeli"


def mysqlreport_native_rows(hostnames, hostvars, result_var="mysqluser"):
    """Audit: sunucudaki tüm mysql_native_password hesapları, kategoriyle.

    Güncel durum kullanılır (Faz 4'te doğrulama sonrası): dönüştürülen hesaplar düşer.
    """
    rows = []
    for name in sorted(hostnames or []):
        hv = _hv(hostvars, name)
        res = hv.get(result_var) or {}
        if res.get("status") != "CHECKED":
            res = hv.get("mysqluser_before") or {}
        for acc in res.get("native_password_accounts", []):
            cat, issue = _native_category(acc)
            rows.append({"server": name, "environment": hv.get("mysql_env", ""),
                         "account": acc, "category": cat, "issue": issue})
    return rows


def mysqlreport_count_by(rows, key):
    counts = {}
    for r in rows or []:
        counts[r[key]] = counts.get(r[key], 0) + 1
    return dict(sorted(counts.items()))


def mysqlreport_counts(rows):
    return mysqlreport_count_by(rows, "status")


def mysqlreport_table(rows, columns=None):
    """Sabit genişlikli metin tablo (AAP job çıktısında okunur)."""
    columns = columns or ["server", "environment", "ip", "port", "status", "method", "version", "detail"]
    if not rows:
        return "(kayıt yok)"
    widths = {c: min(120, max(len(c), *(len(str(r.get(c, ""))) for r in rows))) for c in columns}

    def fmt(r):
        return " | ".join(str(r.get(c, ""))[:widths[c]].ljust(widths[c]) for c in columns)

    header = fmt({c: c.upper() for c in columns})
    sep = "-+-".join("-" * widths[c] for c in columns)
    return "\n".join([header, sep] + [fmt(r) for r in rows])


def mysqlreport_lines(rows, columns=None):
    """Tabloyu satır listesi olarak döndür (AAP JSON çıktısında okunur kalsın)."""
    return mysqlreport_table(rows, columns).splitlines()


class FilterModule(object):
    def filters(self):
        return {
            "mysqlreport_account_rows": mysqlreport_account_rows,
            "mysqlreport_apply_rows": mysqlreport_apply_rows,
            "mysqlreport_native_rows": mysqlreport_native_rows,
            "mysqlreport_rows": mysqlreport_rows,
            "mysqlreport_counts": mysqlreport_counts,
            "mysqlreport_count_by": mysqlreport_count_by,
            "mysqlreport_table": mysqlreport_table,
            "mysqlreport_lines": mysqlreport_lines,
        }
