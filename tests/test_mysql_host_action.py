"""mysql_host_run action plugin: sahte uzak shell ile hata yolları.

Gerçek SSH/MySQL yerine _probe/_sh taklit edilir; amaç, her koşulda istisnanın
yakalanıp sonuca yazıldığını (host'un fail olmadığını) doğrulamaktır.
"""
import os
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "roles", "mysql_host", "action_plugins"))
from ansible.errors import AnsibleConnectionFailure  # noqa: E402
import mysql_host_run as plug  # noqa: E402

ARGS = {"mode": "deploy", "port": 3316, "admin_user": "root", "admin_password": "Adm#1",
        "connect_method": "auto", "client_candidates": ["/usr/bin/mysql"], "tmp_dir": "/tmp",
        "inputs": {"user": "app", "hosts": ["%"], "privilege_sets": ["readonly"], "mismatch_action": "report"},
        "target_password": "Hedef#Sifre1"}
CONN_ROW = "8.0.36\th\t3316\troot@localhost\t0\t0\n"


class Fake(plug.ActionModule):
    """ActionBase kurucusunu atlayan, komutları senaryoya göre yanıtlayan sahte."""

    def __init__(self, script):  # noqa
        self.script, self.calls, self.stdin = script, [], []

    def _probe(self):
        return self._answer("echo SSH_OK", None)

    def _sh(self, cmd, in_data=None):
        return self._answer(cmd, in_data)

    def _answer(self, cmd, in_data):
        self.calls.append(cmd)
        if in_data:
            self.stdin.append(in_data)
        for key, resp in self.script:
            if key in cmd:
                if isinstance(resp, Exception):
                    raise resp
                return dict({"rc": 0, "stdout": "", "stderr": ""}, **resp)
        return {"rc": 0, "stdout": "", "stderr": ""}


BASE = [("echo SSH_OK", {"stdout": "SSH_OK"}), ("command -v mysql", {"stdout": "/usr/bin/mysql"}),
        ("mktemp", {"stdout": "/tmp/.ans_mycnf_abc"}), ("SELECT VERSION()", {"stdout": CONN_ROW}),
        ("SHOW GLOBAL VARIABLES", {"stdout": ""})]


def test_ssh_unreachable_is_recorded_not_raised():
    f = Fake([("echo SSH_OK", AnsibleConnectionFailure("ssh: connect to host x port 22: Connection timed out"))])
    facts = f._execute(ARGS, False)
    assert facts["mysqlconn"]["status"] == "SSH_UNREACHABLE"
    assert "mysqlapply" in facts and facts["mysqlapply"]["status"] == "SKIPPED_CONNECTION"


def test_connection_lost_during_apply_marks_unknown_and_cleans_up():
    f = Fake(BASE + [("--protocol=TCP", {"stdout": CONN_ROW})])
    orig = f._mysql

    def mysql(conn_args, sql=None, stdin=None):
        if stdin:   # uygulama adımı
            raise AnsibleConnectionFailure("Connection reset by peer")
        if sql and "FROM mysql.user" in sql:
            return {"rc": 0, "stdout": "", "stderr": ""}   # hesap yok -> CREATE planı
        return orig(conn_args, sql=sql, stdin=stdin)
    f._mysql = mysql
    facts = f._execute(ARGS, False)
    assert facts["mysqlconn"]["status"] == "OK"
    assert facts["mysqlapply"]["status"] == "UNKNOWN"
    assert "koptu" in facts["mysqlapply"]["detail"]
    assert facts["mysqlhost_error"]["stage"] == "apply"
    assert any(c.startswith("rm -f") for c in f.calls)          # temizlik denendi


def test_unexpected_exception_is_host_error():
    f = Fake(BASE[:2] + [("mktemp", {"rc": 1, "stderr": "mktemp: Permission denied"})])
    facts = f._execute(ARGS, False)
    assert facts["mysqlconn"]["status"] == "HOST_ERROR"
    assert "Permission denied" in facts["mysqlconn"]["detail"]


def test_check_mode_runs_no_sql_with_password_and_secrets_not_in_commands():
    f = Fake(BASE)
    facts = f._execute(ARGS, True)
    assert facts["mysqlapply"]["status"] == "CHECK_MODE"
    assert all("Hedef#Sifre1" not in s for s in f.stdin)        # hedef şifre hiç gönderilmedi
    assert all("Adm#1" not in c and "Hedef#Sifre1" not in c for c in f.calls)   # komut satırında şifre yok
    assert any("Adm#1" in s for s in f.stdin)                    # admin şifresi sadece stdin ile


def test_run_mode_sends_target_password_only_via_stdin():
    f = Fake(BASE)
    facts = f._execute(ARGS, False)
    assert facts["mysqlapply"]["status"] == "APPLIED"
    assert facts.get("mysqluser_post_checked") is True
    assert any("Hedef#Sifre1" in s and s.startswith("CREATE USER") for s in f.stdin)
    assert all("Hedef#Sifre1" not in c for c in f.calls)


@pytest.mark.parametrize("bad_port", ["abc", None])
def test_bad_args_never_raise(bad_port):
    f = Fake(BASE)
    facts = f._execute(dict(ARGS, port=bad_port), False)
    assert facts["mysqlconn"]["status"] in ("OK", "HOST_ERROR")
