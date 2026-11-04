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
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns}
    widths["detail"] = min(widths.get("detail", 0), 120)

    def fmt(r):
        return " | ".join(str(r.get(c, ""))[:widths[c]].ljust(widths[c]) for c in columns)

    header = fmt({c: c.upper() for c in columns})
    sep = "-+-".join("-" * widths[c] for c in columns)
    return "\n".join([header, sep] + [fmt(r) for r in rows])


class FilterModule(object):
    def filters(self):
        return {
            "mysqlreport_rows": mysqlreport_rows,
            "mysqlreport_counts": mysqlreport_counts,
            "mysqlreport_table": mysqlreport_table,
        }
