# -*- coding: utf-8 -*-
"""mysql_host_run: bir MySQL sunucusundaki tüm işi TEK task'ta yapar.

Neden action plugin:
  * Log: host başına ~30 task yerine 1 satır (ok / changed).
  * Dayanıklılık: hiçbir koşulda fail/unreachable döndürmez. SSH kopması, SQL hatası,
    beklenmeyen istisna -> sonuç kaydına yazılır, diğer host'lar ve rapor etkilenmez.
    (Ansible'da bir play'deki TÜM host'lar fail olursa sonraki play - rapor - çalışmaz.)
  * Hedefte Python gerekmez: yalnızca shell komutları ve dosya transferi kullanılır.

Mantık, test edilmiş filtrelerden gelir (mysqlconn / mysqluser / mysqlapply);
burada sadece sıralama ve uzak komut çalıştırma vardır.

mode:
  connect : SSH + mysql client + root ile SELECT VERSION()           (Faz 2)
  check   : + hesap / şifre hash / yetki / şifre politikası kontrolü   (Faz 3)
  deploy  : + plan uygulama + doğrulama (check mode'da uygulanmaz)     (Faz 4)

Güvenlik: admin ve hedef şifre komut satırına hiç yazılmaz. Admin şifresi SSH stdin
ile uzakta mktemp (umask 077, 0600) option file'a yazılır ve iş bitince silinir;
hedef şifreyi içeren SQL betiği mysql'e doğrudan SSH stdin ile verilir (dosyaya yazılmaz).
Task no_log: true ile çağrılır; dönen sonuçta şifre yoktur.
"""
from __future__ import annotations

import os
import shlex
import sys

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.action import ActionBase

_ROLES = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
for _r in ("mysql_connectivity", "mysql_user_check", "mysql_user_apply"):
    _p = os.path.join(_ROLES, _r, "filter_plugins")
    if _p not in sys.path:
        sys.path.insert(0, _p)

import mysqlapply as app  # noqa: E402
import mysqlconn as conn  # noqa: E402
import mysqluser as usr  # noqa: E402

SKIP = {"skipped": True}
CONN_SQL = ("SELECT VERSION(), @@hostname, @@port, CURRENT_USER(), "
            "@@global.read_only, @@global.super_read_only")
FIND_CLIENT = (
    "p=$(bash -lc 'command -v mysql' 2>/dev/null | tail -n1); "
    "if [ -n \"$p\" ] && [ -x \"$p\" ]; then echo \"$p\"; exit 0; fi; "
    "for c in %s; do if [ -x \"$c\" ]; then echo \"$c\"; exit 0; fi; done; exit 3"
)
POST_CHECK_STATES = ("APPLIED", "PARTIAL", "FAILED")


class ActionModule(ActionBase):
    TRANSFERS_FILES = False          # kendi mktemp dosyalarımızı yönetiyoruz
    _supports_check_mode = True

    # ------------------------------------------------------------------ yardımcılar
    def _sh(self, cmd, in_data=None):
        r = self._low_level_execute_command(cmd, sudoable=False, in_data=in_data)
        return {"rc": r.get("rc"), "stdout": to_text(r.get("stdout", "")),
                "stderr": to_text(r.get("stderr", ""))}

    def _probe(self):
        """İlk SSH denemesi. Komut şifre içermez; no_log geçici olarak kapatılır ki
        SSH hata metni (timeout, permission denied...) raporda görünsün."""
        pcs = [pc for pc in (self._play_context, getattr(self._connection, "_play_context", None)) if pc]
        saved = [(pc, pc.no_log) for pc in pcs]
        try:
            for pc in pcs:
                pc.no_log = False
            return self._sh("echo SSH_OK")
        finally:
            for pc, val in saved:
                pc.no_log = val

    def _remote_file(self, content, prefix):
        """content'i uzakta 0600 geçici dosyaya yaz (SSH stdin ile; sftp/scp gerekmez,
        içerik komut satırında görünmez). Yolu döndür."""
        tmpl = shlex.quote("%s/%sXXXXXX" % (self._tmp_dir.rstrip("/"), prefix))
        r = self._sh('umask 077 && f=$(mktemp %s) && cat > "$f" && echo "$f"' % tmpl, in_data=content)
        lines = r["stdout"].strip().splitlines()
        if r["rc"] != 0 or not lines:
            raise RuntimeError("Uzak geçici dosya yazılamadı: %s" % conn._clean(r["stderr"]))
        self._remote_files.append(lines[-1].strip())
        return lines[-1].strip()

    def _cleanup(self):
        if not self._remote_files:
            return
        try:
            self._sh("rm -f %s" % " ".join(shlex.quote(p) for p in self._remote_files))
        except Exception:   # bağlantı kopmuşsa temizlik yapılamaz; raporu etkilemesin
            pass

    def _mysql(self, conn_args, sql=None, stdin=None):
        parts = [self._client, "--defaults-extra-file=" + self._cnf] + conn_args + [
            "--connect-timeout=%s" % self._timeout, "--batch", "--skip-column-names",
            "--default-character-set=utf8mb4"]
        if sql is not None:
            parts.append("--execute=" + sql)
        return self._sh(" ".join(shlex.quote(p) for p in parts), in_data=stdin)

    # ------------------------------------------------------------------ adımlar
    def _connect(self, a):
        try:
            ssh = self._probe()
        except AnsibleConnectionFailure as e:
            return conn.mysqlconn_classify({"unreachable": True, "msg": to_text(e)}, SKIP, SKIP, SKIP)

        cands = " ".join(shlex.quote(c) for c in a.get("client_candidates") or [])
        client = self._sh(FIND_CLIENT % cands) if "SSH_OK" in ssh["stdout"] else {}
        tcp = sock = SKIP
        if client.get("rc") == 0 and client["stdout"].strip():
            self._client = client["stdout"].strip().splitlines()[-1].strip()
            self._cnf = self._remote_file(
                conn.mysqlconn_cnf(a["admin_password"], a.get("admin_user", "root")), ".ans_mycnf_")
            method = a.get("connect_method", "auto")
            if method in ("tcp", "auto"):
                tcp = self._mysql(self._tcp_args, sql=CONN_SQL)
            if conn.mysqlconn_should_fallback(tcp, method):
                sock = self._mysql(["--protocol=SOCKET"], sql=CONN_SQL)
        return conn.mysqlconn_classify(ssh, client, tcp, sock, self._port)

    def _check(self, a, conn_args):
        inputs = a["inputs"]
        r = self._mysql(conn_args, sql=usr.mysqluser_account_sql(inputs["user"]))
        if r["rc"] != 0:
            return {"status": "QUERY_ERROR", "detail": conn._clean(r["stderr"]),
                    "accounts": [], "native_password_accounts": []}
        parsed = usr.mysqluser_parse_accounts(r["stdout"])
        grants_out = ""
        if parsed["accounts"]:
            g = self._mysql(conn_args, sql=usr.mysqluser_grants_sql(parsed["accounts"]))
            if g["rc"] != 0:
                return {"status": "QUERY_ERROR", "detail": conn._clean(g["stderr"]),
                        "accounts": [], "native_password_accounts": []}
            grants_out = g["stdout"]
        ev = usr.mysqluser_evaluate(inputs, parsed, usr.mysqluser_parse_grants(grants_out),
                                    a["target_password"], a.get("admin_user", "root"))
        return dict({"status": "CHECKED", "detail": ""}, **ev)

    def _apply(self, a, c, before, conn_args):
        plan = app.mysqlapply_plan(before.get("accounts", []))
        blocked = app.mysqlapply_blocked(before.get("accounts", []))
        planned = [dict(p, result="PLANNED", error="") for p in plan] + blocked

        if not plan:
            return {"status": "BLOCKED_PASSWORD_POLICY" if blocked else "NO_CHANGE",
                    "detail": "", "results": blocked}
        if c.get("read_only"):
            return {"status": "SKIPPED_READ_ONLY", "results": planned,
                    "detail": "read_only/super_read_only: değişiklik primary üzerinden replike olur"}
        if c.get("port_mismatch"):
            return {"status": "SKIPPED_PORT_MISMATCH", "results": planned,
                    "detail": "Envanter portu %s, bağlanılan instance @@port %s; yanlış instance riski"
                              % (self._port, c.get("server_port", "?"))}
        if self._check_mode:
            return {"status": "CHECK_MODE", "results": planned, "detail": "Check mode: SQL çalıştırılmadı"}

        # SQL betiği (hedef şifreyi içerir) mysql'e doğrudan SSH stdin ile verilir
        r = self._mysql(conn_args, stdin=app.mysqlapply_script(plan, a["target_password"]))
        results = app.mysqlapply_result(plan, r["rc"], r["stderr"]) + blocked
        failed = [x["error"] for x in results if x["result"] in ("FAILED", "UNKNOWN")]
        return {"status": app.mysqlapply_status(results), "results": results,
                "detail": failed[0] if failed else ""}

    # ------------------------------------------------------------------ run
    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        facts = self._execute(self._task.args, bool(self._task.check_mode))
        applied = any(r.get("result") == "APPLIED" for r in facts.get("mysqlapply", {}).get("results", []))
        result.update(changed=applied, failed=False, ansible_facts=facts)
        return result

    def _execute(self, a, check_mode):
        """Tüm iş; hiçbir istisna dışarı çıkmaz (unit test edilebilir)."""
        mode = a.get("mode", "connect")
        self._remote_files, self._client, self._cnf = [], "", ""
        facts = {"mysqlconn": {}, "mysqlhost_mode": mode}
        stage = "connect"
        try:
            self._check_mode = check_mode
            self._port = int(a.get("port") or 3316)
            self._timeout = int(a.get("connect_timeout") or 10)
            self._tmp_dir = a.get("tmp_dir") or "/tmp"
            self._tcp_args = ["--protocol=TCP", "--host=127.0.0.1", "--port=%d" % self._port]
            c = facts["mysqlconn"] = self._connect(a)
            if mode in ("check", "deploy") and c.get("status") == "OK":
                conn_args = self._tcp_args if c.get("method") == "tcp" else ["--protocol=SOCKET"]
                stage = "check"
                before = self._check(a, conn_args)
                facts.update(mysqluser=before, mysqluser_before=before)
                if mode == "deploy":
                    stage = "apply"
                    if before["status"] != "CHECKED":
                        facts["mysqlapply"] = {"status": "SKIPPED_CHECK_ERROR", "results": [],
                                               "detail": before.get("detail", "")}
                    else:
                        ap = facts["mysqlapply"] = self._apply(a, c, before, conn_args)
                        if ap["status"] in POST_CHECK_STATES:
                            stage = "verify"
                            facts["mysqluser"] = self._check(a, conn_args)
                            facts["mysqluser_post_checked"] = True
            elif mode == "deploy":
                facts["mysqlapply"] = {"status": "SKIPPED_CONNECTION", "results": [], "detail": ""}
        except AnsibleConnectionFailure as e:
            self._record_error(facts, stage, "SSH bağlantısı işlem sırasında koptu: " + conn._clean(to_text(e)))
        except Exception as e:   # beklenmeyen her durum raporlanır, host fail edilmez
            self._record_error(facts, stage, "%s: %s" % (type(e).__name__, conn._clean(to_text(e))))
        finally:
            self._cleanup()
        return facts

    @staticmethod
    def _record_error(facts, stage, msg):
        facts["mysqlhost_error"] = {"stage": stage, "detail": msg}
        c = facts.setdefault("mysqlconn", {})
        if c.get("status") != "OK":
            c.update(status="HOST_ERROR", detail=msg)
        elif stage == "check":
            facts["mysqluser"] = facts["mysqluser_before"] = {
                "status": "QUERY_ERROR", "detail": msg, "accounts": [], "native_password_accounts": []}
        elif stage in ("apply", "verify"):
            ap = facts.setdefault("mysqlapply", {"results": []})
            # uygulama sırasında kopma: hangi ifadelerin çalıştığı bilinmiyor
            if stage == "apply":
                ap.update(status="UNKNOWN", detail=msg)
            else:
                ap["detail"] = (ap.get("detail") or "") + " | doğrulama yapılamadı: " + msg
