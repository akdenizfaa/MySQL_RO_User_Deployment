"""Faz 3 filtre testleri: python3 -m pytest -q tests/

Hash vektörleri ve SHOW GRANTS örnekleri gerçek MySQL 8.0.46'dan alınmıştır.
"""
import json
import os
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "roles", "mysql_user_check", "filter_plugins"))
sys.path.insert(0, os.path.join(HERE, "..", "roles", "mysql_report", "filter_plugins"))
import mysqluser as u  # noqa: E402
import mysqlreport as r  # noqa: E402

with open(os.path.join(HERE, "fixtures", "mysql8_hash_vectors.json"), encoding="utf-8") as fh:
    VECTORS = json.load(fh)
with open(os.path.join(HERE, "fixtures", "mysql8_show_grants.txt"), encoding="utf-8") as fh:
    GRANTS_TXT = fh.read()


# ---------------------------------------------------------------- hash
@pytest.mark.parametrize("vec", VECTORS, ids=lambda v: "%s-%d" % (v["plugin"][:6], len(v["password"])))
def test_real_mysql_hash_vectors(vec):
    assert u.mysqluser_password_matches(vec["password"], vec["plugin"], vec["auth_hex"]) is True
    assert u.mysqluser_password_matches(vec["password"] + "x", vec["plugin"], vec["auth_hex"]) is False


def test_hash_unsupported_and_malformed():
    assert u.mysqluser_password_matches("a", "auth_socket", "") is None
    assert u.mysqluser_password_matches("a", "caching_sha2_password", "2441") is None   # kısa
    assert u.mysqluser_password_matches("a", "caching_sha2_password", "zz") is None     # hex değil
    assert u.mysqluser_password_matches("a", "caching_sha2_password", "") is False      # şifresiz hesap
    assert u.mysqluser_password_matches("a", "mysql_native_password", "") is False


# ---------------------------------------------------------------- validate
def test_validate_ok_and_defaults():
    v = u.mysqluser_validate("app_ro", True, "", ["readonly", "DML"], "Update")
    assert v == {"user": "app_ro", "hosts": ["%"], "privilege_sets": ["readonly", "dml"],
                 "mismatch_action": "update"}


def test_validate_multiselect_string_and_hosts():
    v = u.mysqluser_validate("app", True, "%, 10.230.%,\n10.236.%", "readonly\nddl", "report")
    assert v["hosts"] == ["%", "10.230.%", "10.236.%"]
    assert v["privilege_sets"] == ["readonly", "ddl"]


@pytest.mark.parametrize("kwargs,msg", [
    (dict(user="root"), "Sistem hesabı"),
    (dict(user="a'b"), "Kullanıcı adı geçersiz"),
    (dict(user="x" * 33), "Kullanıcı adı geçersiz"),
    (dict(password=False), "şifresi boş"),
    (dict(hosts="10.0.0.%' OR 1=1 --"), "Geçersiz host"),
    (dict(sets=[]), "En az bir yetki seti"),
    (dict(sets=["admin"]), "Geçersiz yetki seti"),
    (dict(action="delete"), "report' veya 'update"),
])
def test_validate_errors(kwargs, msg):
    args = dict(user="app", password=True, hosts="%", sets=["readonly"], action="report")
    args.update(kwargs)
    with pytest.raises(ValueError, match=msg):
        u.mysqluser_validate(args["user"], args["password"], args["hosts"], args["sets"], args["action"])


# ---------------------------------------------------------------- desired
def test_desired_union_without_duplicates():
    d = u.mysqluser_desired(["readonly", "dml", "ddl"])
    assert d["privileges"].count("SELECT") == 1 and d["privileges"].count("SHOW VIEW") == 1
    assert "EXECUTE" not in d["privileges"]
    assert d["grant_option"] is False and d["all"] is False


def test_desired_superuser_variants():
    assert u.mysqluser_desired(["superuser"]) == {"privileges": ["ALL PRIVILEGES"], "grant_option": False, "all": True}
    assert u.mysqluser_desired(["readonly", "superuser_with_grant"])["grant_option"] is True


# ---------------------------------------------------------------- sql
def test_sql_escaping():
    assert "user = 'ab'" in u.mysqluser_account_sql("ab")
    assert u.mysqluser_grants_sql([{"user": "a", "host": "10.%"}]) == "SHOW GRANTS FOR 'a'@'10.%';"
    assert u._q("x'y\\z") == "'x\\'y\\\\z'"


# ---------------------------------------------------------------- parse
def test_parse_real_show_grants():
    g = u.mysqluser_parse_grants(GRANTS_TXT)
    assert g["app_ro@%"]["global_privs"] == ["SELECT"]
    assert g["app_ro@10.230.%"]["global_privs"] == ["USAGE"]
    assert u.CORE_ALL_PRIVILEGES <= set(g["app_su@%"]["global_privs"])   # ALL açılmış hali
    assert g["app_su@%"]["grant_option"] is False
    assert g["root@localhost"]["grant_option"] is True


def test_parse_accounts():
    out = ("N\tlegacy\tlocalhost\tmysql_native_password\t\tN\t\n"
           "U\tapp\t%\tcaching_sha2_password\tABCD\tY\tN\n")
    p = u.mysqluser_parse_accounts(out)
    assert p["native"] == [{"user": "legacy", "host": "localhost", "plugin": "mysql_native_password",
                            "account_locked": False, "password_expired": False}]
    assert p["accounts"][0]["auth_hex"] == "ABCD" and p["accounts"][0]["account_locked"] is True


# ---------------------------------------------------------------- evaluate
def _vec(plugin, password):
    return [v for v in VECTORS if v["plugin"] == plugin and v["password"] == password][0]["auth_hex"]


def test_evaluate_all_statuses():
    inputs = u.mysqluser_validate("app", True, "%,10.230.%,10.236.%", ["readonly"], "report")
    parsed = {"accounts": [
        {"user": "app", "host": "%", "plugin": "caching_sha2_password",
         "auth_hex": _vec("caching_sha2_password", "Basit123")},
        {"user": "app", "host": "10.230.%", "plugin": "mysql_native_password",
         "auth_hex": _vec("mysql_native_password", "a"), "account_locked": True},
        {"user": "app", "host": "10.99.%", "plugin": "caching_sha2_password", "auth_hex": ""},
    ], "native": [{"user": "app", "host": "10.230.%"}, {"user": "legacy", "host": "localhost"}]}
    grants = u.mysqluser_parse_grants("GRANT SELECT, SHOW VIEW ON *.* TO `app`@`%`\n"
                                      "GRANT USAGE ON *.* TO `app`@`10.230.%`")
    res = u.mysqluser_evaluate(inputs, parsed, grants, "Basit123")
    by = {a["account"]: a for a in res["accounts"]}

    assert by["app@%"]["status"] == "EXISTS_PASSWORD_MATCH"
    assert by["app@%"]["missing_privileges"] == [] and by["app@%"]["statements"] == []

    a = by["app@10.230.%"]
    assert a["status"] == "EXISTS_PASSWORD_DIFFERENT"
    assert "NATIVE_PASSWORD_DÜZELTİLMELİ" in a["flags"] and "ACCOUNT_LOCKED" in a["flags"]
    assert "ŞİFRE_FARKLI_SADECE_RAPOR" in a["flags"]                   # report modu: ALTER yok
    assert [st["kind"] for st in a["statements"]] == ["GRANT"]
    assert a["missing_privileges"] == ["SELECT", "SHOW VIEW"]

    n = by["app@10.236.%"]
    assert n["status"] == "NOT_EXISTS"
    assert n["planned_actions"] == [
        "CREATE USER 'app'@'10.236.%' IDENTIFIED WITH caching_sha2_password BY '********'",
        "GRANT SELECT, SHOW VIEW ON *.* TO 'app'@'10.236.%'"]
    assert by["app@10.99.%"]["status"] == "EXTRA_ACCOUNT"
    assert res["native_password_accounts"] == ["app@10.230.%", "legacy@localhost"]


def test_evaluate_update_and_grant_option():
    inputs = u.mysqluser_validate("app", True, "%", ["superuser_with_grant"], "update")
    parsed = {"accounts": [{"user": "app", "host": "%", "plugin": "caching_sha2_password",
                            "auth_hex": _vec("caching_sha2_password", "Basit123")}], "native": []}
    grants = u.mysqluser_parse_grants(GRANTS_TXT.replace("`app_su`@`%`", "`app`@`%`"))
    a = u.mysqluser_evaluate(inputs, parsed, grants, "baska")["accounts"][0]
    assert a["status"] == "EXISTS_PASSWORD_DIFFERENT"
    assert a["missing_privileges"] == []                      # ALL açılmış hali tanındı
    assert a["planned_actions"] == [
        "ALTER USER 'app'@'%' IDENTIFIED WITH caching_sha2_password BY '********'",
        "GRANT USAGE ON *.* TO 'app'@'%' WITH GRANT OPTION"]


def test_evaluate_existing_grant_option_is_flag_only():
    inputs = u.mysqluser_validate("app", True, "%", ["readonly"], "report")
    parsed = {"accounts": [{"user": "app", "host": "%", "plugin": "caching_sha2_password",
                            "auth_hex": _vec("caching_sha2_password", "a")}], "native": []}
    grants = u.mysqluser_parse_grants("GRANT SELECT, SHOW VIEW ON *.* TO `app`@`%` WITH GRANT OPTION")
    a = u.mysqluser_evaluate(inputs, parsed, grants, "a")["accounts"][0]
    assert a["flags"] == ["MEVCUT_GRANT_OPTION"] and a["planned_actions"] == []


def test_extra_privileges_reported_not_revoked():
    inputs = u.mysqluser_validate("app", True, "%", ["readonly"], "report")
    parsed = {"accounts": [{"user": "app", "host": "%", "plugin": "caching_sha2_password",
                            "auth_hex": _vec("caching_sha2_password", "a")}], "native": []}
    grants = u.mysqluser_parse_grants("GRANT SELECT, SHOW VIEW, INSERT, DROP ON *.* TO `app`@`%`\n"
                                      "GRANT ALL PRIVILEGES ON `crm`.* TO `app`@`%`")
    a = u.mysqluser_evaluate(inputs, parsed, grants, "a")["accounts"][0]
    assert a["extra_privileges"] == ["INSERT", "DROP"]
    assert a["other_grants"] == ["GRANT ALL PRIVILEGES ON `crm`.* TO `app`@`%`"]
    assert "FAZLA_YETKİ" in a["flags"] and a["statements"] == []      # REVOKE yok


def test_native_with_update_converts_plugin():
    inputs = u.mysqluser_validate("app", True, "%", ["readonly"], "update")
    parsed = {"accounts": [{"user": "app", "host": "%", "plugin": "mysql_native_password",
                            "auth_hex": _vec("mysql_native_password", "a")}], "native": []}
    grants = u.mysqluser_parse_grants("GRANT SELECT, SHOW VIEW ON *.* TO `app`@`%`")
    a = u.mysqluser_evaluate(inputs, parsed, grants, "yeni")["accounts"][0]
    assert a["statements"][0]["template"] == (
        "ALTER USER 'app'@'%' IDENTIFIED WITH caching_sha2_password BY " + u.PW_TOKEN)


def test_render_inserts_escaped_password_only_at_apply():
    t = "CREATE USER 'a'@'%' IDENTIFIED WITH caching_sha2_password BY " + u.PW_TOKEN
    assert u.mysqluser_render(t, "x'y\\z") == t.replace(u.PW_TOKEN, "'x\\'y\\\\z'") + ";"
    with pytest.raises(ValueError):
        u.mysqluser_render(t, "a\nb")


# ---------------------------------------------------------------- report
def test_report_account_and_native_rows():
    hv = {
        "s1": {"mysql_env": "TEST", "mysqluser": {"status": "CHECKED", "accounts": [
            {"account": "app@%", "status": "NOT_EXISTS", "plugin": "", "password": "",
             "missing_privileges": ["SELECT"], "flags": [], "planned_actions": ["CREATE USER"]}],
            "native_password_accounts": ["legacy@localhost"]}},
        "s2": {"mysql_env": "PROD", "mysqluser": {"status": "SKIPPED_CONNECTION",
                                                 "detail": "Bağlantı durumu SSH_UNREACHABLE"}},
    }
    rows = r.mysqlreport_account_rows(["s2", "s1"], hv)
    assert [(x["server"], x["status"]) for x in rows] == [("s1", "NOT_EXISTS"), ("s2", "SKIPPED_CONNECTION")]
    assert rows[1]["planned"] == "Bağlantı durumu SSH_UNREACHABLE"
    assert r.mysqlreport_native_rows(["s1", "s2"], hv)[0]["account"] == "legacy@localhost"
    assert r.mysqlreport_lines(rows, ["server", "status"])[0].startswith("SERVER")
