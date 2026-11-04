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


def mysqlreport_account_rows(hostnames, hostvars, result_var="mysqluser"):
    """Faz 3: sunucu x hesap satırları. Bağlantısı olmayan sunucu tek satır alır."""
    rows = []
    for name in sorted(hostnames or []):
        hv = hostvars.get(name, {}) if hasattr(hostvars, "get") else hostvars[name]
        res = hv.get(result_var) or {}
        base = {"server": name, "environment": hv.get("mysql_env", "")}
        if res.get("status") != "CHECKED":
            rows.append(dict(base, account="-", status=res.get("status") or "ERROR",
                             plugin="", password="", missing="", flags="",
                             planned=res.get("detail", "") if res else "Sonuç üretilemedi"))
            continue
        for a in res.get("accounts", []):
            rows.append(dict(base, account=a["account"], status=a["status"], plugin=a["plugin"],
                             password=a["password"], missing=", ".join(a["missing_privileges"]),
                             flags=", ".join(a["flags"]), planned="; ".join(a["planned_actions"])))
    return rows


def mysqlreport_native_rows(hostnames, hostvars, result_var="mysqluser"):
    """Audit: sunucudaki tüm mysql_native_password hesapları (düzeltilmeli)."""
    rows = []
    for name in sorted(hostnames or []):
        hv = hostvars.get(name, {}) if hasattr(hostvars, "get") else hostvars[name]
        res = hv.get(result_var) or {}
        for acc in res.get("native_password_accounts", []):
            rows.append({"server": name, "environment": hv.get("mysql_env", ""),
                         "account": acc, "issue": "mysql_native_password -> caching_sha2_password'e geçirilmeli"})
    return rows


def mysqlreport_counts(rows):
    counts = {}
    for r in rows or []:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return dict(sorted(counts.items()))


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
            "mysqlreport_native_rows": mysqlreport_native_rows,
            "mysqlreport_rows": mysqlreport_rows,
            "mysqlreport_counts": mysqlreport_counts,
            "mysqlreport_table": mysqlreport_table,
            "mysqlreport_lines": mysqlreport_lines,
        }
