"""Faz 2 filtre testleri: python3 -m pytest -q tests/"""
import os
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "roles", "mysql_connectivity", "filter_plugins"))
sys.path.insert(0, os.path.join(HERE, "..", "roles", "mysql_report", "filter_plugins"))
import mysqlconn as c  # noqa: E402
import mysqlreport as r  # noqa: E402

SSH_OK = {"rc": 0, "stdout": "SSH_OK\r\n"}
CLIENT_OK = {"rc": 0, "stdout": "/usr/bin/mysql"}
SKIP = {"skipped": True}


def run(rc, stdout="", stderr=""):
    return {"rc": rc, "stdout": stdout, "stderr": stderr}


def test_ssh_unreachable():
    rec = c.mysqlconn_classify({"unreachable": True, "msg": "ssh: connect to host 10.0.0.1 port 22: Connection timed out"}, SKIP, SKIP, SKIP)
    assert rec["status"] == "SSH_UNREACHABLE"


def test_ssh_auth_fail_and_noise_removed():
    msg = ("Task failed: Failed to connect to the host via ssh: Warning: Permanently added '10.0.0.1' "
           "(ED25519) to the list of known hosts. uxsqlteam@10.0.0.1: Permission denied (publickey,password).")
    rec = c.mysqlconn_classify({"unreachable": True, "msg": msg}, SKIP, SKIP, SKIP)
    assert rec["status"] == "SSH_AUTH_FAIL"
    assert rec["detail"].startswith("uxsqlteam@10.0.0.1: Permission denied")


def test_host_error_when_module_fails():
    rec = c.mysqlconn_classify(SSH_OK, {"failed": True, "msg": "/usr/bin/python: not found"}, SKIP, SKIP)
    assert rec["status"] == "HOST_ERROR"


def test_client_not_found():
    rec = c.mysqlconn_classify(SSH_OK, run(3), SKIP, SKIP)
    assert rec["status"] == "MYSQL_CLIENT_NOT_FOUND"


def test_ok_tcp_parses_columns():
    rec = c.mysqlconn_classify(SSH_OK, CLIENT_OK, run(0, "8.0.36\tgbarkt02\t3316\troot@localhost\n"), SKIP, 3316)
    assert rec["status"] == "OK" and rec["method"] == "tcp"
    assert rec["version"] == "8.0.36" and rec["current_user"] == "root@localhost"
    assert rec["detail"] == "" and rec["port_mismatch"] is False


def test_fallback_socket_ok_with_port_mismatch_note():
    tcp = run(1, stderr="ERROR 2003 (HY000): Can't connect to MySQL server on '127.0.0.1:3399' (111)")
    rec = c.mysqlconn_classify(SSH_OK, CLIENT_OK, tcp, run(0, "8.4.0\th\t3316\troot@localhost"), 3399)
    assert rec["status"] == "OK" and rec["method"] == "socket"
    assert rec["port_mismatch"] is True
    assert "ERROR 2003" in rec["detail"] and "3399" in rec["detail"]


def test_auth_fail_both_methods():
    tcp = run(1, stderr="ERROR 1045 (28000): Access denied for user 'root'@'127.0.0.1' (using password: YES)")
    sock = run(1, stderr="ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)")
    rec = c.mysqlconn_classify(SSH_OK, CLIENT_OK, tcp, sock, 3316)
    assert rec["status"] == "MYSQL_AUTH_FAIL"
    assert rec["detail"].startswith("tcp: ERROR 1045") and "socket: ERROR 1045" in rec["detail"]


@pytest.mark.parametrize("err,status", [
    ("ERROR 2002 (HY000): Can't connect to local MySQL server through socket", "MYSQL_UNREACHABLE"),
    ("ERROR 1130 (HY000): Host '127.0.0.1' is not allowed to connect", "MYSQL_ERROR"),
])
def test_mysql_error_codes(err, status):
    assert c.mysqlconn_classify(SSH_OK, CLIENT_OK, run(1, stderr=err), SKIP)["status"] == status


@pytest.mark.parametrize("err,method,expected", [
    ("ERROR 1045 (28000): Access denied", "auto", True),
    ("ERROR 2003 (HY000): Can't connect", "auto", True),
    ("ERROR 1130 (HY000): Host not allowed", "auto", False),
    ("ERROR 1045 (28000): Access denied", "tcp", False),
])
def test_should_fallback(err, method, expected):
    assert c.mysqlconn_should_fallback(run(1, stderr=err), method) is expected


def test_should_fallback_socket_mode_and_tcp_ok():
    assert c.mysqlconn_should_fallback(SKIP, "socket") is True
    assert c.mysqlconn_should_fallback(run(0, "x"), "auto") is False


@pytest.mark.parametrize("pw", ['Lab#Pw"1\\x', "a'b;c#d", "plain", ""])
def test_cnf_escaping_roundtrip(pw):
    content = c.mysqlconn_cnf(pw, "root")
    line = [l for l in content.splitlines() if l.startswith("password=")][0]
    value = line[len("password="):]
    assert value.startswith('"') and value.endswith('"')
    # option file parser'ı gibi çöz: \\ -> \ , \" -> "
    decoded = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    assert decoded == pw


def test_cnf_rejects_newline():
    with pytest.raises(ValueError):
        c.mysqlconn_cnf("a\nb")


def test_report_rows_counts_and_table():
    hostvars = {
        "s1": {"mysql_env": "TEST", "ansible_host": "10.0.0.1", "mysql_port": 3316,
               "mysqlconn": {"status": "OK", "method": "tcp", "version": "8.0.36", "detail": ""}},
        "s2": {"mysql_env": "PROD", "ansible_host": "10.0.0.2", "mysql_port": 3316},  # sonuç yok
    }
    rows = r.mysqlreport_rows(["s2", "s1"], hostvars, [{"name": "s3", "environment": "TEST", "reason": "isActive=0"}])
    assert [x["server"] for x in rows] == ["s1", "s2", "s3"]
    assert [x["status"] for x in rows] == ["OK", "ERROR", "SKIPPED"]
    assert r.mysqlreport_counts(rows) == {"ERROR": 1, "OK": 1, "SKIPPED": 1}
    table = r.mysqlreport_table(rows).splitlines()
    assert table[0].startswith("SERVER") and len(table) == 5


def test_read_only_detected():
    rec = c.mysqlconn_classify(SSH_OK, CLIENT_OK, run(0, "8.0.36\th\t3306\troot@localhost\t1\t1"), SKIP, 3306)
    assert rec["status"] == "OK" and rec["read_only"] is True
    assert "read_only" in rec["detail"]
    rec = c.mysqlconn_classify(SSH_OK, CLIENT_OK, run(0, "8.0.36\th\t3306\troot@localhost\t0\t0"), SKIP, 3306)
    assert rec["read_only"] is False and rec["detail"] == ""
