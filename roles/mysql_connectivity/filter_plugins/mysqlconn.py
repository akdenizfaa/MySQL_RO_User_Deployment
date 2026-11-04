# -*- coding: utf-8 -*-
"""Faz 2 bağlantı testi sonuçlarını tek bir durum koduna indirger.

Durum kodları (öncelik sırasıyla, ilk başarısız adım belirler):
  SSH_UNREACHABLE        SSH portu/ağ erişimi yok, timeout, host down
  SSH_AUTH_FAIL          SSH kullanıcı/şifre/anahtar reddedildi
  HOST_ERROR             SSH var ama komut çalışmadı (python yok, izin vb.)
  MYSQL_CLIENT_NOT_FOUND mysql client PATH'te ve bilinen yollarda yok
  MYSQL_AUTH_FAIL        ERROR 1045 (kullanıcı/şifre/host eşleşmesi)
  MYSQL_UNREACHABLE      ERROR 2002/2003/2013 (servis kapalı, port/socket yanlış)
  MYSQL_ERROR            diğer MySQL hataları
  OK                     bağlantı ve SELECT başarılı
"""
from __future__ import annotations

import re

SSH_AUTH_PATTERNS = re.compile(
    r"permission denied|authentication failed|incorrect password|"
    r"invalid/incorrect password|too many authentication failures|no authentication methods",
    re.I,
)
MYSQL_ERR_CODE = re.compile(r"ERROR\s+(\d{4})")


def _clean(text, limit=300):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    # SSH/Ansible gürültüsü: asıl hata mesajı okunur kalsın
    text = re.sub(r"Warning: Permanently added .*? to the list of known hosts\.?\s*", "", text)
    text = re.sub(r"^(Task failed:\s*)?(Failed to connect to the host via ssh:\s*)?", "", text)
    # mysql client'ın zararsız uyarısı raporu kirletmesin
    text = text.replace(
        "mysql: [Warning] Using a password on the command line interface can be insecure.", ""
    ).strip()
    return text[:limit]


def _ran(result):
    return isinstance(result, dict) and not result.get("skipped") and "rc" in result


def _mysql_error(result):
    """(status, code, detail) - başarısız mysql çalıştırması için."""
    err = _clean(result.get("stderr") or result.get("msg"))
    m = MYSQL_ERR_CODE.search(err)
    code = m.group(1) if m else ""
    if code == "1045":
        status = "MYSQL_AUTH_FAIL"
    elif code in ("2002", "2003", "2013"):
        status = "MYSQL_UNREACHABLE"
    else:
        status = "MYSQL_ERROR"
    return status, code, err


def mysqlconn_classify(ssh, client, tcp, sock, expected_port=None):
    """Adım sonuçlarından durum kaydı üret.

    ssh, client, tcp, sock: register edilmiş task sonuçları (skipped olabilir).
    """
    rec = {
        "status": "PENDING", "detail": "", "client": "", "method": "",
        "version": "", "server_hostname": "", "server_port": "",
        "current_user": "", "port_mismatch": False, "read_only": False,
    }

    # 1) SSH
    ssh = ssh or {}
    if ssh.get("unreachable") or ssh.get("failed") or "SSH_OK" not in str(ssh.get("stdout", "")):
        msg = _clean(ssh.get("msg") or ssh.get("stderr") or "SSH bağlantısı kurulamadı")
        rec["status"] = "SSH_AUTH_FAIL" if SSH_AUTH_PATTERNS.search(msg) else "SSH_UNREACHABLE"
        rec["detail"] = msg
        return rec

    # 2) mysql client
    client = client or {}
    if "rc" not in client:
        rec["status"] = "HOST_ERROR"
        rec["detail"] = _clean(client.get("msg") or client.get("module_stderr") or "komut çalıştırılamadı")
        return rec
    lines = [l for l in str(client.get("stdout", "")).splitlines() if l.strip()]
    if client.get("rc") != 0 or not lines:
        rec["status"] = "MYSQL_CLIENT_NOT_FOUND"
        rec["detail"] = "mysql client PATH'te ve bilinen yollarda bulunamadı"
        return rec
    rec["client"] = lines[-1].strip()

    # 3) MySQL login: socket denendiyse (tcp fallback ya da direkt) o belirleyicidir
    attempts = []
    if _ran(tcp):
        attempts.append(("tcp", tcp))
    if _ran(sock):
        attempts.append(("socket", sock))
    if not attempts:
        rec["status"] = "HOST_ERROR"
        rec["detail"] = "MySQL bağlantı adımı çalışmadı"
        return rec

    method, final = attempts[-1]
    rec["method"] = method
    if final.get("rc") == 0:
        cols = (str(final.get("stdout", "")).strip().splitlines() or [""])[-1].split("\t")
        cols += [""] * (6 - len(cols))
        rec.update(status="OK", version=cols[0], server_hostname=cols[1],
                   server_port=cols[2], current_user=cols[3],
                   # read_only veya super_read_only: replika / Group Replication secondary.
                   # Faz 4 bu sunuculara yazmaz; değişiklik primary'den replike olur.
                   read_only=(cols[4] == "1" or cols[5] == "1"))
        notes = []
        if method == "socket" and _ran(tcp):
            _, code, _ = _mysql_error(tcp)
            notes.append("TCP başarısız (ERROR %s), socket ile bağlanıldı" % (code or "?"))
        if expected_port and cols[2] and str(cols[2]) != str(expected_port):
            rec["port_mismatch"] = True
            notes.append("Envanter portu %s, sunucu @@port %s" % (expected_port, cols[2]))
        if rec["read_only"]:
            notes.append("read_only (replika/secondary): yazma yapılmaz")
        rec["detail"] = "; ".join(notes)
        return rec

    status, _, err = _mysql_error(final)
    rec["status"] = status
    if len(attempts) == 2:
        _, _, tcp_err = _mysql_error(tcp)
        rec["detail"] = "tcp: %s | socket: %s" % (tcp_err, err)
    else:
        rec["detail"] = err
    return rec


def mysqlconn_should_fallback(tcp_result, method):
    """auto modda TCP sonrası socket denenmeli mi?"""
    if method == "socket":
        return True
    if method != "auto" or not _ran(tcp_result) or tcp_result.get("rc") == 0:
        return False
    _, code, _ = _mysql_error(tcp_result)
    # 2002: MariaDB client TCP'de de 2002 döner; MySQL client 2003 döner
    return code in ("1045", "2002", "2003", "2013")


def mysqlconn_cnf(password, user="root"):
    """MySQL client option file ([client]) içeriği üret.

    Değer çift tırnak içinde yazılır; option file parser'ının tanıdığı \\ ve \"
    kaçışları uygulanır. Jinja'da bu kaçış Ansible sürümüne göre farklı
    yorumlandığı için Python'da yapılır.
    """
    def q(v):
        v = str(v if v is not None else "")
        if "\n" in v or "\r" in v:
            raise ValueError("Kullanıcı/şifre satır sonu içeremez")
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return "[client]\nuser=%s\npassword=%s\n" % (q(user), q(password))


class FilterModule(object):
    def filters(self):
        return {
            "mysqlconn_classify": mysqlconn_classify,
            "mysqlconn_cnf": mysqlconn_cnf,
            "mysqlconn_should_fallback": mysqlconn_should_fallback,
        }
