# -*- coding: utf-8 -*-
"""Faz 3: kullanıcı/hesap kontrolü (salt okunur) - doğrulama, SQL üretimi,
çıktı ayrıştırma, şifre hash karşılaştırma ve yetki farkı.

Şifre kontrolü (mimari karar A): hedef kullanıcının şifresi sunucuya GİTMEZ.
mysql.user'dan plugin + HEX(authentication_string) okunur, survey'deki şifre
aynı algoritma ve salt ile burada (AAP EE içinde) hash'lenip karşılaştırılır.
"""
from __future__ import annotations

import hashlib
import re

# ---------------------------------------------------------------------------
# Yetki setleri (onaylı). Hepsi *.* üzerinde.
# dml'e LOCK TABLES + CREATE TEMPORARY TABLES eklendi (öneri): uygulamaların
# DML iş akışlarında sık gerekir, veri/şema değiştirme kapsamını genişletmez.
# ---------------------------------------------------------------------------
PRIVILEGE_SETS = {
    "readonly": ["SELECT", "SHOW VIEW"],
    "dml": ["SELECT", "INSERT", "UPDATE", "DELETE", "LOCK TABLES", "CREATE TEMPORARY TABLES"],
    "ddl": ["CREATE", "ALTER", "DROP", "INDEX", "REFERENCES", "CREATE VIEW", "SHOW VIEW",
            "CREATE ROUTINE", "ALTER ROUTINE", "TRIGGER", "EVENT"],
    "superuser": ["ALL PRIVILEGES"],
    "superuser_with_grant": ["ALL PRIVILEGES"],   # + WITH GRANT OPTION
}
# SHOW GRANTS MySQL 8'de ALL'u statik yetki listesine açar. Sürümler arası
# farklılık gösterebilen SUPER / REPLICATION * hariç çekirdek liste:
CORE_ALL_PRIVILEGES = {
    "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "RELOAD", "SHUTDOWN",
    "PROCESS", "FILE", "REFERENCES", "INDEX", "ALTER", "SHOW DATABASES",
    "CREATE TEMPORARY TABLES", "LOCK TABLES", "EXECUTE", "CREATE VIEW", "SHOW VIEW",
    "CREATE ROUTINE", "ALTER ROUTINE", "CREATE USER", "EVENT", "TRIGGER",
    "CREATE TABLESPACE", "CREATE ROLE", "DROP ROLE",
}

USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,31}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.%_:\-/]{1,255}$")
MISMATCH_ACTIONS = ("report", "update")

_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


# ---------------------------------------------------------------------------
# Girdi doğrulama
# ---------------------------------------------------------------------------
def _split(value):
    if value is None:
        return []
    if isinstance(value, str):
        value = re.split(r"[,\n;]+", value)
    out = []
    for v in value:
        item = str(v).strip().strip("\"'").strip()
        if item and item not in out:
            out.append(item)
    return out


def mysqluser_validate(user, password, hosts, privilege_sets, mismatch_action):
    """Survey girdilerini doğrula; normalize edilmiş dict döndür.

    Hata varsa ValueError (mesajda şifre yer almaz).
    """
    errors = []
    user = str(user or "").strip()
    if not USER_RE.match(user):
        errors.append("Kullanıcı adı geçersiz: harf/rakam/_ . - ve en fazla 32 karakter olmalı")
    if user.lower() in ("root", "mysql.sys", "mysql.session", "mysql.infoschema"):
        errors.append("Sistem hesabı hedeflenemez: %s" % user)
    if not password:
        errors.append("Hedef kullanıcı şifresi boş")
    elif "\n" in str(password) or "\r" in str(password):
        errors.append("Şifre satır sonu içeremez")

    host_list = _split(hosts) or ["%"]
    bad_hosts = [h for h in host_list if not HOST_RE.match(h)]
    if bad_hosts:
        errors.append("Geçersiz host: %s" % bad_hosts)

    sets = [s.lower() for s in _split(privilege_sets)]
    bad_sets = [s for s in sets if s not in PRIVILEGE_SETS]
    if not sets:
        errors.append("En az bir yetki seti seçilmeli: %s" % list(PRIVILEGE_SETS))
    if bad_sets:
        errors.append("Geçersiz yetki seti: %s" % bad_sets)

    action = str(mismatch_action or "report").strip().lower()
    if action not in MISMATCH_ACTIONS:
        errors.append("password_mismatch_action 'report' veya 'update' olmalı")

    if errors:
        raise ValueError("; ".join(errors))
    return {"user": user, "hosts": host_list, "privilege_sets": sets,
            "mismatch_action": action}


def mysqluser_desired(privilege_sets):
    """Seçilen setlerin birleşimi -> {privileges: [...], grant_option: bool, all: bool}"""
    sets = [s.lower() for s in _split(privilege_sets)]
    is_all = any(s in ("superuser", "superuser_with_grant") for s in sets)
    privs = []
    if is_all:
        privs = ["ALL PRIVILEGES"]
    else:
        for s in sets:
            for p in PRIVILEGE_SETS[s]:
                if p not in privs:
                    privs.append(p)
    return {"privileges": privs, "grant_option": "superuser_with_grant" in sets, "all": is_all}


# ---------------------------------------------------------------------------
# SQL üretimi (girdiler mysqluser_validate'ten geçmiş olmalı)
# ---------------------------------------------------------------------------
def _q(value):
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def mysqluser_account_sql(user):
    """Hedef kullanıcının tüm hesapları (U) + sunucudaki native password hesapları (N)."""
    return (
        "SELECT 'U', user, host, plugin, HEX(authentication_string), account_locked, password_expired "
        "FROM mysql.user WHERE user = %s "
        "UNION ALL "
        "SELECT 'N', user, host, plugin, '', account_locked, '' "
        "FROM mysql.user WHERE plugin = 'mysql_native_password' "
        "ORDER BY 1, 2, 3; "
        # Şifre politikası (validate_password component veya eski plugin). Satırlar 2 sütun.
        "SHOW GLOBAL VARIABLES LIKE 'validate%%password%%'" % _q(user)
    )


def mysqluser_grants_sql(accounts):
    """[{'user','host'}] -> tek çağrıda SHOW GRANTS."""
    return " ".join("SHOW GRANTS FOR %s@%s;" % (_q(a["user"]), _q(a["host"])) for a in accounts)


# ---------------------------------------------------------------------------
# Çıktı ayrıştırma
# ---------------------------------------------------------------------------
def mysqluser_parse_accounts(stdout):
    """mysqluser_account_sql batch çıktısı -> {'accounts': [...], 'native': [...]}"""
    accounts, native, policy = [], [], {}
    for line in str(stdout or "").splitlines():
        cols = line.split("\t")
        if len(cols) == 2 and cols[0].lower().startswith("validate"):
            # eski plugin adlandırması (validate_password_length) -> component (validate_password.length)
            name = cols[0].lower().replace("validate_password_", "validate_password.")
            policy[name] = cols[1]
            continue
        if len(cols) < 7:
            continue
        kind, user, host, plugin, auth_hex, locked, expired = cols[:7]
        rec = {"user": user, "host": host, "plugin": plugin,
               "account_locked": locked == "Y", "password_expired": expired == "Y"}
        if kind == "U":
            rec["auth_hex"] = auth_hex
            accounts.append(rec)
        elif kind == "N":
            native.append(rec)
    return {"accounts": accounts, "native": native, "password_policy": policy}


# ---------------------------------------------------------------------------
# Şifre politikası (validate_password) yerel değerlendirmesi
# Şifre sunucuya GÖNDERİLMEZ; MySQL kuralları burada uygulanır.
# ---------------------------------------------------------------------------
_POLICY_NAMES = {"0": "LOW", "1": "MEDIUM", "2": "STRONG"}


def _int(v, default=0):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def mysqluser_password_policy_check(password, policy, user_names=()):
    """validate_password kurallarına göre değerlendir.

    Dönen: {active, ok, policy, rules, reasons[], unchecked[]}
    active=False -> sunucuda politika yok (her şifre kabul).
    """
    if not policy or "validate_password.policy" not in policy:
        return {"active": False, "ok": True, "policy": "", "rules": {}, "reasons": [], "unchecked": []}
    pw = str(password)
    level = str(policy.get("validate_password.policy", "1")).strip().upper()
    level = _POLICY_NAMES.get(level, level)
    mixed = _int(policy.get("validate_password.mixed_case_count"), 1)
    number = _int(policy.get("validate_password.number_count"), 1)
    special = _int(policy.get("validate_password.special_char_count"), 1)
    # MySQL, length'i bu toplamdan küçük olamayacak şekilde ayarlar
    length = max(_int(policy.get("validate_password.length"), 8), number + special + 2 * mixed)
    rules = {"policy": level, "length": length, "mixed_case_count": mixed,
             "number_count": number, "special_char_count": special}
    reasons, unchecked = [], []

    if len(pw) < length:
        reasons.append("en az %d karakter olmalı (şu an %d)" % (length, len(pw)))
    if level in ("MEDIUM", "STRONG"):
        lower = sum(1 for ch in pw if ch.islower())
        upper = sum(1 for ch in pw if ch.isupper())
        digits = sum(1 for ch in pw if ch.isdigit())
        specials = sum(1 for ch in pw if not ch.isalnum())
        if lower < mixed or upper < mixed:
            reasons.append("en az %d küçük ve %d büyük harf olmalı" % (mixed, mixed))
        if digits < number:
            reasons.append("en az %d rakam olmalı" % number)
        if specials < special:
            reasons.append("en az %d özel karakter olmalı" % special)
    if level == "STRONG" and str(policy.get("validate_password.dictionary_file", "")).strip():
        unchecked.append("sözlük kontrolü (dictionary_file) yerelde yapılamaz")

    check_name = str(policy.get("validate_password.check_user_name", "ON")).upper() in ("ON", "1")
    if check_name:
        for name in user_names:
            if name and (pw.lower() == name.lower() or pw.lower() == name.lower()[::-1]):
                reasons.append("kullanıcı adıyla aynı veya tersi olamaz")
                break
    return {"active": True, "ok": not reasons, "policy": level, "rules": rules,
            "reasons": reasons, "unchecked": unchecked}


_GRANT_RE = re.compile(r"^GRANT (?P<privs>.+?) ON (?P<obj>\S+) TO (?P<to>`[^`]*`@`[^`]*`|'[^']*'@'[^']*')(?P<rest>.*)$")
_TO_RE = re.compile(r"^[`'](?P<user>.*)[`']@[`'](?P<host>.*)[`']$")


def mysqluser_parse_grants(stdout):
    """SHOW GRANTS satırları -> {'user@host': {global_privs, grant_option, raw:[...]}}"""
    out = {}
    for line in str(stdout or "").splitlines():
        line = line.strip()
        m = _GRANT_RE.match(line)
        if not m:
            continue
        t = _TO_RE.match(m.group("to"))
        if not t:
            continue
        key = "%s@%s" % (t.group("user"), t.group("host").lower())
        rec = out.setdefault(key, {"global_privs": [], "grant_option": False, "raw": []})
        rec["raw"].append(line)
        if m.group("obj") == "*.*":
            for p in m.group("privs").split(","):
                p = re.sub(r"\s+", " ", p.strip().upper())
                if p == "ALL":
                    p = "ALL PRIVILEGES"
                if p and p not in rec["global_privs"]:
                    rec["global_privs"].append(p)
            if "WITH GRANT OPTION" in m.group("rest").upper():
                rec["grant_option"] = True
    return out


# ---------------------------------------------------------------------------
# Şifre hash doğrulama
# ---------------------------------------------------------------------------
def _native_hash(password):
    stage = hashlib.sha1(hashlib.sha1(password.encode("utf-8")).digest()).hexdigest().upper()
    return "*" + stage


def _sha256_crypt(password, salt, rounds):
    """Drepper SHA-256 crypt (MySQL caching_sha2_password'ün kullandığı gövde).

    MySQL farkı: salt 20 bayt (standart crypt 16'da keser).
    """
    p, s = password, salt
    b = hashlib.sha256(p + s + p).digest()
    ctx = hashlib.sha256(p + s)
    n = len(p)
    while n > 32:
        ctx.update(b)
        n -= 32
    ctx.update(b[:n])
    n = len(p)
    while n > 0:
        ctx.update(b if n & 1 else p)
        n >>= 1
    a = ctx.digest()

    dp = hashlib.sha256(p * len(p)).digest()
    p_seq = (dp * (len(p) // 32 + 1))[:len(p)]
    ds = hashlib.sha256(s * (16 + a[0])).digest()
    s_seq = (ds * (len(s) // 32 + 1))[:len(s)]

    c = a
    for i in range(rounds):
        ctx = hashlib.sha256()
        ctx.update(p_seq if i & 1 else c)
        if i % 3:
            ctx.update(s_seq)
        if i % 7:
            ctx.update(p_seq)
        ctx.update(c if i & 1 else p_seq)
        c = ctx.digest()

    order = [(0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
             (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29)]
    out = []
    for b2, b1, b0 in order:
        w = (c[b2] << 16) | (c[b1] << 8) | c[b0]
        for _ in range(4):
            out.append(_B64[w & 0x3F])
            w >>= 6
    w = (c[31] << 8) | c[30]
    for _ in range(3):
        out.append(_B64[w & 0x3F])
        w >>= 6
    return "".join(out).encode("ascii")


def mysqluser_password_matches(password, plugin, auth_hex):
    """True / False / None (desteklenmeyen plugin veya bozuk hash)."""
    try:
        auth = bytes.fromhex(auth_hex or "")
    except ValueError:
        return None
    pw = str(password)
    if plugin == "mysql_native_password":
        if not auth:
            return False
        return auth.decode("ascii", "replace").upper() == _native_hash(pw)
    if plugin == "caching_sha2_password":
        if not auth:
            return False
        # $A$<3 hex: iterasyon/1000>$<20 bayt salt><43 karakter hash>
        if not auth.startswith(b"$A$") or len(auth) != 7 + 20 + 43 or auth[6:7] != b"$":
            return None
        rounds = int(auth[3:6].decode("ascii"), 16) * 1000
        salt, digest = auth[7:27], auth[27:]
        return _sha256_crypt(pw.encode("utf-8"), salt, rounds) == digest
    return None


# ---------------------------------------------------------------------------
# Değerlendirme + Faz 4 SQL planı
# ---------------------------------------------------------------------------
PW_TOKEN = "__TARGET_PASSWORD__"
AUTH_PLUGIN = "caching_sha2_password"   # yeni/güncellenen hesaplar her zaman bu plugin


def _has_all(cur):
    return "ALL PRIVILEGES" in cur or CORE_ALL_PRIVILEGES <= cur


def _missing(desired, current):
    cur = set(current.get("global_privs", []))
    if desired["all"]:
        return [] if _has_all(cur) else ["ALL PRIVILEGES"]
    if _has_all(cur):
        return []
    return [p for p in desired["privileges"] if p not in cur]


def _extra(desired, current):
    """Seçilenden fazla *.* yetkileri (REVOKE edilmez, sadece raporlanır)."""
    if desired["all"]:
        return []
    cur = [p for p in current.get("global_privs", []) if p != "USAGE"]
    if _has_all(set(cur)):
        return ["ALL PRIVILEGES"]
    return [p for p in cur if p not in desired["privileges"]]


def _other_grants(current):
    """*.* dışındaki grant satırları (şema/tablo seviyesi) - bilgi amaçlı."""
    return [g for g in current.get("raw", [])
            if " ON *.* TO " not in g and not g.startswith("GRANT PROXY ON ``@``")]


def _acct(user, host):
    return "%s@%s" % (_q(user), _q(host))


def _stmt(kind, template):
    return {"kind": kind, "template": template, "masked": template.replace(PW_TOKEN, "'********'")}


def mysqluser_evaluate(inputs, parsed, grants, password, admin_user="root"):
    """Hesap bazlı sonuç + Faz 4 SQL planı + sunucu audit'i.

    Her hesapta 'statements': [{kind, template, masked}]. template içinde şifre
    yerine PW_TOKEN bulunur; gerçek SQL yalnızca uygulama anında
    mysqluser_render ile (no_log task içinde) üretilir.
    """
    desired = mysqluser_desired(inputs["privilege_sets"])
    user = inputs["user"]
    existing = {a["host"].lower(): a for a in parsed.get("accounts", [])}
    # check_user_name: MySQL yalnızca oturum kullanıcısının adıyla karşılaştırır
    # (hedef hesabın adıyla değil) - MySQL 8.0.46 ile doğrulandı.
    policy = mysqluser_password_policy_check(password, parsed.get("password_policy", {}),
                                             (admin_user,))
    grant_suffix = " WITH GRANT OPTION" if desired["grant_option"] else ""
    results = []

    for host in inputs["hosts"]:
        acc = existing.get(host.lower())
        acct = _acct(user, host)
        res = {"account": "%s@%s" % (user, host), "host": host, "plugin": "", "password": "",
               "missing_privileges": [], "extra_privileges": [], "other_grants": [],
               "current_privileges": [], "flags": [], "statements": []}

        if acc is None:
            res["status"] = "NOT_EXISTS"
            res["missing_privileges"] = list(desired["privileges"])
            res["statements"] = [
                _stmt("CREATE_USER", "CREATE USER %s IDENTIFIED WITH %s BY %s"
                      % (acct, AUTH_PLUGIN, PW_TOKEN)),
                _stmt("GRANT", "GRANT %s ON *.* TO %s%s"
                      % (", ".join(desired["privileges"]), acct, grant_suffix)),
            ]
            results.append(res)
            continue

        res["plugin"] = acc["plugin"]
        match = mysqluser_password_matches(password, acc["plugin"], acc.get("auth_hex"))
        if match is None:
            res["status"], res["password"] = "UNSUPPORTED_PLUGIN", "UNKNOWN"
        elif match:
            res["status"], res["password"] = "EXISTS_PASSWORD_MATCH", "MATCH"
            if acc["plugin"] == "mysql_native_password":
                if inputs["mismatch_action"] == "update":
                    # Şifre aynı; yalnızca plugin dönüşümü (sadece hedef kullanıcı)
                    res["statements"].append(_stmt(
                        "ALTER_USER_PLUGIN", "ALTER USER %s IDENTIFIED WITH %s BY %s"
                        % (acct, AUTH_PLUGIN, PW_TOKEN)))
                else:
                    res["flags"].append("NATIVE_DÖNÜŞÜM_İÇİN_UPDATE_GEREKİR")
        else:
            res["status"], res["password"] = "EXISTS_PASSWORD_DIFFERENT", "DIFFERENT"
            if inputs["mismatch_action"] == "update":
                # IDENTIFIED WITH caching_sha2_password: native hesaplar da dönüştürülür
                res["statements"].append(_stmt(
                    "ALTER_USER_PASSWORD", "ALTER USER %s IDENTIFIED WITH %s BY %s"
                    % (acct, AUTH_PLUGIN, PW_TOKEN)))
            else:
                res["flags"].append("ŞİFRE_FARKLI_SADECE_RAPOR")

        if acc["plugin"] == "mysql_native_password":
            res["flags"].append("NATIVE_PASSWORD_DÜZELTİLMELİ")
        if acc.get("account_locked"):
            res["flags"].append("ACCOUNT_LOCKED")
        if acc.get("password_expired"):
            res["flags"].append("PASSWORD_EXPIRED")

        cur = grants.get("%s@%s" % (user, host.lower()), {})
        res["current_privileges"] = cur.get("global_privs", [])
        res["missing_privileges"] = _missing(desired, cur)
        res["extra_privileges"] = _extra(desired, cur)
        res["other_grants"] = _other_grants(cur)
        need_go = desired["grant_option"] and not cur.get("grant_option")
        if res["missing_privileges"]:
            res["statements"].append(_stmt("GRANT", "GRANT %s ON *.* TO %s%s" % (
                ", ".join(res["missing_privileges"]), acct, " WITH GRANT OPTION" if need_go else "")))
        elif need_go:
            res["statements"].append(_stmt(
                "GRANT", "GRANT USAGE ON *.* TO %s WITH GRANT OPTION" % acct))
        if cur.get("grant_option") and not desired["grant_option"]:
            res["flags"].append("MEVCUT_GRANT_OPTION")
        if res["extra_privileges"] or res["other_grants"]:
            res["flags"].append("FAZLA_YETKİ")
        results.append(res)

    requested = set(h.lower() for h in inputs["hosts"])
    for host, acc in sorted(existing.items()):
        if host not in requested:
            cur = grants.get("%s@%s" % (user, host), {})
            results.append({
                "account": "%s@%s" % (user, acc["host"]), "host": acc["host"],
                "status": "EXTRA_ACCOUNT", "plugin": acc["plugin"], "password": "",
                "missing_privileges": [], "extra_privileges": [], "other_grants": _other_grants(cur),
                "current_privileges": cur.get("global_privs", []),
                "flags": ["SURVEY_HOST_LISTESİNDE_YOK"]
                + (["NATIVE_PASSWORD_DÜZELTİLMELİ"] if acc["plugin"] == "mysql_native_password" else []),
                "statements": [],
            })

    # Şifre politikası: şifre içeren ifadeler politikayı geçemiyorsa engellenir.
    # Hesap yoksa (CREATE USER engellendi) aynı hesabın GRANT'ı da engellenir.
    if policy["active"] and not policy["ok"]:
        reason = "şifre politikası (%s): %s" % (policy["policy"], "; ".join(policy["reasons"]))
        for r in results:
            pw_blocked = False
            for st in r["statements"]:
                if PW_TOKEN in st["template"]:
                    st["blocked"] = reason
                    pw_blocked = True
            if pw_blocked:
                r["flags"].append("ŞİFRE_POLİTİKASI_UYGUN_DEĞİL")
                if r["status"] == "NOT_EXISTS":
                    for st in r["statements"]:
                        st.setdefault("blocked", "hesap oluşturulamadığı için")
    for r in results:
        r["planned_actions"] = [st["masked"] + (" [ENGELLENDİ: %s]" % st["blocked"] if st.get("blocked") else "")
                                for st in r["statements"]]
    native = ["%s@%s" % (n["user"], n["host"]) for n in parsed.get("native", [])]
    return {"accounts": results, "native_password_accounts": native,
            "password_policy": {k: v for k, v in policy.items()}}


def mysqluser_render(template, password):
    """Uygulama anında gerçek SQL (yalnızca no_log task içinde kullanılır)."""
    if "\n" in str(password) or "\r" in str(password):
        raise ValueError("Şifre satır sonu içeremez")
    return template.replace(PW_TOKEN, _q(password)) + ";"


class FilterModule(object):
    def filters(self):
        return {
            "mysqluser_validate": mysqluser_validate,
            "mysqluser_desired": mysqluser_desired,
            "mysqluser_account_sql": mysqluser_account_sql,
            "mysqluser_grants_sql": mysqluser_grants_sql,
            "mysqluser_parse_accounts": mysqluser_parse_accounts,
            "mysqluser_parse_grants": mysqluser_parse_grants,
            "mysqluser_password_matches": mysqluser_password_matches,
            "mysqluser_password_policy_check": mysqluser_password_policy_check,
            "mysqluser_evaluate": mysqluser_evaluate,
            "mysqluser_render": mysqluser_render,
        }
