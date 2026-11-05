"""Sonuç raporu testleri (mysqlreport_build)."""
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "roles", "mysql_report", "filter_plugins"))
import mysqlreport as r  # noqa: E402

INPUTS = {"user": "app", "hosts": ["%"], "privilege_sets": ["readonly"], "mismatch_action": "report"}
CONN_OK = {"status": "OK", "method": "tcp", "version": "8.0.36", "detail": "", "read_only": False}


def _acc(status="NOT_EXISTS", statements=None, flags=None, **kw):
    a = {"account": "app@%", "status": status, "plugin": "", "password": "", "flags": flags or [],
         "missing_privileges": [], "extra_privileges": [], "other_grants": [],
         "statements": statements or [], "planned_actions": []}
    a.update(kw)
    return a


CREATE = [{"kind": "CREATE_USER", "template": "CREATE USER 'app'@'%' ... BY __TARGET_PASSWORD__", "masked": "CREATE ..."},
          {"kind": "GRANT", "template": "GRANT SELECT, SHOW VIEW ON *.* TO 'app'@'%'", "masked": "GRANT ..."}]


def _user(accounts, native=None, policy=None):
    return {"status": "CHECKED", "accounts": accounts, "native_password_accounts": native or [],
            "password_policy": policy or {}}


def build(hostvars, phase="deploy", skipped=None, check_mode=False):
    return r.mysqlreport_build(list(hostvars), hostvars, skipped,
                               {"phase": phase, "title": "T", "check_mode": check_mode,
                                "environments": ["TEST"], "inputs": INPUTS})


def test_deploy_categories_grouping_and_failures():
    applied = _user([_acc(statements=CREATE)])
    post = _user([_acc(status="EXISTS_PASSWORD_MATCH")])
    hv = {
        "s1": {"mysqlconn": CONN_OK, "mysqluser_before": applied, "mysqluser": post,
               "mysqluser_post_checked": True,
               "mysqlapply": {"status": "APPLIED", "results": [
                   {"account": "app@%", "kind": "CREATE_USER", "masked": "CREATE ...", "result": "APPLIED", "error": ""},
                   {"account": "app@%", "kind": "GRANT", "masked": "GRANT ...", "result": "APPLIED", "error": ""}]}},
        "s2": {"mysqlconn": {"status": "SSH_UNREACHABLE", "detail": "Connection timed out"}},
        "s3": {"mysqlconn": dict(CONN_OK, read_only=True), "mysqluser_before": applied,
               "mysqlapply": {"status": "SKIPPED_READ_ONLY", "results": [], "detail": "ro"}},
        "s4": {"mysqlconn": CONN_OK, "mysqluser_before": _user([_acc(status="EXISTS_PASSWORD_MATCH")]),
               "mysqlapply": {"status": "NO_CHANGE", "results": []}},
        "s5": {"mysqlconn": CONN_OK, "mysqluser_before": _user([_acc(status="EXISTS_PASSWORD_MATCH")]),
               "mysqlapply": {"status": "NO_CHANGE", "results": []}},
        "s6": {"ansible_facts": {"mysqlconn": CONN_OK,                       # action plugin: facts namespace
                                 "mysqluser_before": _user([_acc(status="EXISTS_PASSWORD_DIFFERENT",
                                                                 flags=["ŞİFRE_FARKLI_SADECE_RAPOR"])]),
                                 "mysqlapply": {"status": "NO_CHANGE", "results": []}}},
        "s7": {},                                                             # host görevi hiç çalışmadı
    }
    rep = build(hv, skipped=[{"name": "p1", "environment": "TEST", "reason": "isActive=0"}])
    cats = {h["server"]: h["category"] for h in rep["hosts"]}
    assert cats == {"s1": "DONE", "s2": "ERROR", "s3": "REPLICA", "s4": "OK", "s5": "OK",
                    "s6": "REPORT_ONLY", "s7": "ERROR", "p1": "SKIPPED"}
    msg = {h["server"]: h["message"] for h in rep["hosts"]}
    assert msg["s1"] == "app@%: oluşturuldu, yetkiler verildi; doğrulama: OK"
    assert msg["s2"].startswith("SSH bağlantısı kurulamadı: Connection timed out")
    text = "\n".join(rep["lines"])
    assert "  - s4, s5: Hesap, şifre ve yetkiler uygun" in text        # gruplama
    assert "Sonuç        : 2 hata, 1 değişiklik yapıldı" in text
    assert rep["summary"]["failed_servers"] == ["s2", "s7"]
    assert len(rep["apply"]) == 2 and rep["apply"][0]["result"] == "APPLIED"


def test_large_groups_wrap_host_names():
    ok = {"mysqlconn": CONN_OK, "mysqluser_before": _user([_acc(status="EXISTS_PASSWORD_MATCH")]),
          "mysqlapply": {"status": "NO_CHANGE", "results": []}}
    hv = {"h%02d" % i: ok for i in range(14)}
    lines = build(hv)["lines"]
    i = lines.index("  - Hesap, şifre ve yetkiler uygun (14 sunucu):")
    assert lines[i + 1].strip().count(",") == 5 and lines[i + 3].strip() == "h12, h13"


def test_policy_block_partial_failure_port_and_check_mode():
    blocked = [dict(CREATE[0], blocked="şifre politikası"), dict(CREATE[1], blocked="hesap oluşturulamadığı için")]
    pol = {"policy": "MEDIUM", "reasons": ["en az 1 rakam olmalı"], "ok": False, "active": True}
    hv = {
        "b": {"mysqlconn": CONN_OK, "mysqluser_before": _user([_acc(statements=blocked)], policy=pol),
              "mysqlapply": {"status": "BLOCKED_PASSWORD_POLICY", "results": []}},
        "f": {"mysqlconn": CONN_OK, "mysqluser_before": _user([_acc(statements=CREATE)]),
              "mysqlapply": {"status": "PARTIAL", "detail": "ERROR 1227: Access denied", "results": [
                  {"account": "app@%", "kind": "CREATE_USER", "masked": "C", "result": "APPLIED", "error": ""},
                  {"account": "app@%", "kind": "GRANT", "masked": "G", "result": "FAILED", "error": "ERROR 1227"}]}},
        "p": {"mysqlconn": dict(CONN_OK, port_mismatch=True), "mysqluser_before": _user([_acc(statements=CREATE)]),
              "mysqlapply": {"status": "SKIPPED_PORT_MISMATCH", "detail": "Envanter portu 3399", "results": []}},
        "u": {"mysqlconn": CONN_OK, "mysqluser_before": _user([_acc(statements=CREATE)]),
              "mysqlapply": {"status": "UNKNOWN", "detail": "SSH bağlantısı işlem sırasında koptu", "results": []}},
    }
    rep = build(hv)
    by = {h["server"]: h for h in rep["hosts"]}
    assert by["b"]["category"] == "BLOCKED" and "en az 1 rakam" in by["b"]["message"]
    assert by["f"]["category"] == "ERROR" and "uygulananlar: app@% CREATE_USER" in by["f"]["message"]
    assert by["p"]["category"] == "BLOCKED"
    assert by["u"]["category"] == "ERROR" and "belirsiz" in by["u"]["message"]
    assert rep["summary"]["failed_servers"] == ["b", "f", "p", "u"]

    chk = build({"c": {"mysqlconn": CONN_OK, "mysqluser_before": _user([_acc(statements=CREATE)]),
                       "mysqlapply": {"status": "CHECK_MODE", "results": []}}}, check_mode=True)
    assert chk["hosts"][0]["category"] == "PLANNED"
    assert chk["hosts"][0]["message"] == "app@%: oluşturulacak, yetkiler verilecek"
    assert "[CHECK]" in chk["lines"][1]


def test_check_and_connect_phases_and_notes():
    acc = _acc(status="EXISTS_PASSWORD_MATCH", plugin="mysql_native_password",
               flags=["FAZLA_YETKİ", "NATIVE_DÖNÜŞÜM_İÇİN_UPDATE_GEREKİR"], extra_privileges=["INSERT"])
    extra = _acc(status="EXTRA_ACCOUNT", account="app@10.%")
    hv = {"a": {"mysqlconn": dict(CONN_OK, method="socket"),
                "mysqluser": _user([acc, extra], native=["app@%", "root@localhost", "mysql_router1_x@%"])}}
    rep = build(hv, phase="check")
    assert rep["hosts"][0]["category"] == "OK"
    text = "\n".join(rep["lines"])
    for needle in ("Fazla yetki, REVOKE edilmedi (app@%: INSERT): a",
                   "Survey'de olmayan ek hesap (app@10.%): a",
                   "TCP ile bağlanılamadı, socket kullanıldı: a",
                   "mysql_native_password audit: 3 hesap / 1 sunucu",
                   "CLUSTER_ROUTER_İÇ_HESAP: 1 hesap", "ROOT: 1 hesap", "UYGULAMA_SERVİS: 1 hesap"):
        assert needle in text, needle

    con = build({"a": {"mysqlconn": dict(CONN_OK, detail="read_only (replika/secondary): yazma yapılmaz")}},
                phase="connect")
    assert con["hosts"][0] == {"server": "a", "environment": "", "ip": "", "category": "CONNECTED",
                               "message": "MySQL 8.0.36 (tcp) - read_only (replika/secondary): yazma yapılmaz"}
