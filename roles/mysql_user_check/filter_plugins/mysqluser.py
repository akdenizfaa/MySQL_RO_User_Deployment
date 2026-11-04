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
        "ORDER BY 1, 2, 3" % _q(user)
    )


def mysqluser_grants_sql(accounts):
    """[{'user','host'}] -> tek çağrıda SHOW GRANTS."""
    return " ".join("SHOW GRANTS FOR %s@%s;" % (_q(a["user"]), _q(a["host"])) for a in accounts)


# ---------------------------------------------------------------------------
# Çıktı ayrıştırma
# ---------------------------------------------------------------------------
def mysqluser_parse_accounts(stdout):
    """mysqluser_account_sql batch çıktısı -> {'accounts': [...], 'native': [...]}"""
    accounts, native = [], []
    for line in str(stdout or "").splitlines():
        cols = line.split("\t")
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
    return {"accounts": accounts, "native": native}


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
# Değerlendirme
# ---------------------------------------------------------------------------
def _missing(desired, current):
    cur = set(current.get("global_privs", []))
    if desired["all"]:
        ok = "ALL PRIVILEGES" in cur or CORE_ALL_PRIVILEGES <= cur
        return [] if ok else ["ALL PRIVILEGES"]
    if "ALL PRIVILEGES" in cur or CORE_ALL_PRIVILEGES <= cur:
        return []
    return [p for p in desired["privileges"] if p not in cur]


def mysqluser_evaluate(inputs, parsed, grants, password):
    """Hesap bazlı sonuç listesi + sunucu audit'i.

    inputs : mysqluser_validate çıktısı
    parsed : mysqluser_parse_accounts çıktısı
    grants : mysqluser_parse_grants çıktısı
    """
    desired = mysqluser_desired(inputs["privilege_sets"])
    existing = {a["host"].lower(): a for a in parsed.get("accounts", [])}
    results = []

    for host in inputs["hosts"]:
        account = "%s@%s" % (inputs["user"], host)
        acc = existing.get(host.lower())
        res = {"account": account, "host": host, "plugin": "", "password": "",
               "missing_privileges": [], "current_privileges": [], "flags": [],
               "planned_actions": []}
        if acc is None:
            res["status"] = "NOT_EXISTS"
            res["missing_privileges"] = list(desired["privileges"])
            res["planned_actions"] = ["CREATE USER", "GRANT %s%s" % (
                ", ".join(desired["privileges"]), " WITH GRANT OPTION" if desired["grant_option"] else "")]
            results.append(res)
            continue

        res["plugin"] = acc["plugin"]
        match = mysqluser_password_matches(password, acc["plugin"], acc.get("auth_hex"))
        if match is None:
            res["status"] = "UNSUPPORTED_PLUGIN"
            res["password"] = "UNKNOWN"
        elif match:
            res["status"] = "EXISTS_PASSWORD_MATCH"
            res["password"] = "MATCH"
        else:
            res["status"] = "EXISTS_PASSWORD_DIFFERENT"
            res["password"] = "DIFFERENT"
            res["planned_actions"].append(
                "ALTER USER (şifre güncelle)" if inputs["mismatch_action"] == "update"
                else "YOK (sadece rapor)")

        if acc["plugin"] == "mysql_native_password":
            res["flags"].append("NATIVE_PASSWORD_DÜZELTİLMELİ")
        if acc.get("account_locked"):
            res["flags"].append("ACCOUNT_LOCKED")
        if acc.get("password_expired"):
            res["flags"].append("PASSWORD_EXPIRED")

        cur = grants.get("%s@%s" % (inputs["user"], host.lower()), {})
        res["current_privileges"] = cur.get("global_privs", [])
        res["missing_privileges"] = _missing(desired, cur)
        if res["missing_privileges"]:
            res["planned_actions"].append("GRANT %s" % ", ".join(res["missing_privileges"]))
        if desired["grant_option"] and not cur.get("grant_option"):
            res["planned_actions"].append("GRANT OPTION ekle")
        if cur.get("grant_option") and not desired["grant_option"]:
            res["flags"].append("MEVCUT_GRANT_OPTION")   # bilgi: Faz 4 yetki geri almaz
        results.append(res)

    requested = set(h.lower() for h in inputs["hosts"])
    for host, acc in sorted(existing.items()):
        if host not in requested:
            results.append({
                "account": "%s@%s" % (inputs["user"], acc["host"]), "host": acc["host"],
                "status": "EXTRA_ACCOUNT", "plugin": acc["plugin"], "password": "",
                "missing_privileges": [], "current_privileges":
                    grants.get("%s@%s" % (inputs["user"], host), {}).get("global_privs", []),
                "flags": ["SURVEY_HOST_LISTESİNDE_YOK"]
                + (["NATIVE_PASSWORD_DÜZELTİLMELİ"] if acc["plugin"] == "mysql_native_password" else []),
                "planned_actions": ["YOK (bilgi)"],
            })

    native = ["%s@%s" % (n["user"], n["host"]) for n in parsed.get("native", [])]
    return {"accounts": results, "native_password_accounts": native}


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
            "mysqluser_evaluate": mysqluser_evaluate,
        }
