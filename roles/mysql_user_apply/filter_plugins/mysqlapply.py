# -*- coding: utf-8 -*-
"""Faz 4: plan düzleştirme, SQL script üretimi ve uygulama sonucunun
ifade bazında ayrıştırılması."""
from __future__ import annotations

import os
import re
import sys

# mysqluser_render'ı tekrar yazmamak için Faz 3 filtresini kullan
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "mysql_user_check", "filter_plugins"))
import mysqluser  # noqa: E402

_ERR_LINE = re.compile(r"ERROR\s+(?P<code>\d{4})(?:\s+\([^)]*\))?\s+at line\s+(?P<line>\d+)(?:\s+in file:[^:]*)?:\s*(?P<msg>.*)", re.S)


def mysqlapply_plan(accounts):
    """Hesap sonuçlarındaki ifadeleri sıralı tek listeye çevir."""
    plan = []
    for a in accounts or []:
        for st in a.get("statements", []):
            plan.append({"account": a["account"], "kind": st["kind"],
                         "template": st["template"], "masked": st["masked"]})
    return plan


def mysqlapply_script(plan, password):
    """Her ifade ayrı satırda: mysql client hata satır numarası = ifade sırası.

    Bu çıktı yalnızca no_log task'ın stdin'ine verilir.
    """
    return "\n".join(mysqluser.mysqluser_render(p["template"], password) for p in plan) + "\n"


def mysqlapply_result(plan, rc, stderr=""):
    """rc/stderr -> ifade bazlı sonuç.

    mysql client --batch modda ilk hatada durur ve 'ERROR <kod> at line <n>' yazar.
    1..n-1 uygulanmış, n hata, n+1.. çalışmamış kabul edilir.
    """
    out = []
    if rc == 0:
        return [dict(p, result="APPLIED", error="") for p in plan]
    m = _ERR_LINE.search(str(stderr or ""))
    failed_at = int(m.group("line")) if m else None
    err = ("ERROR %s: %s" % (m.group("code"), m.group("msg").strip())) if m else str(stderr or "").strip()
    for i, p in enumerate(plan, start=1):
        if failed_at is None:
            out.append(dict(p, result="UNKNOWN", error=err[:300]))
        elif i < failed_at:
            out.append(dict(p, result="APPLIED", error=""))
        elif i == failed_at:
            out.append(dict(p, result="FAILED", error=err[:300]))
        else:
            out.append(dict(p, result="NOT_RUN", error=""))
    return out


def mysqlapply_status(results):
    """Sunucu seviyesi özet durum."""
    states = set(r["result"] for r in results or [])
    if not results:
        return "NO_CHANGE"
    if states == {"APPLIED"}:
        return "APPLIED"
    if "APPLIED" in states:
        return "PARTIAL"
    return "FAILED"


class FilterModule(object):
    def filters(self):
        return {
            "mysqlapply_plan": mysqlapply_plan,
            "mysqlapply_script": mysqlapply_script,
            "mysqlapply_result": mysqlapply_result,
            "mysqlapply_status": mysqlapply_status,
        }
