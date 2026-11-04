# -*- coding: utf-8 -*-
"""MSSQL My_ServerInventory satırlarını normalize eden ve hedef seçen filtreler.

Neden filter plugin: eşleme/doğrulama mantığı Jinja içinde okunaksız ve test
edilemez olur; Python'da tek yerde, unit-test ile doğrulanabilir.
"""
from __future__ import annotations

import re

VALID_ENVS = ("DEV", "TEST", "QA", "PROD")


def _s(value):
    """None/boşluk -> '' ; diğerlerini trim'li string yap."""
    if value is None:
        return ""
    return str(value).strip()


def _truthy(value):
    return _s(value).lower() in ("1", "true", "yes", "y")


def mysqlinv_envs(value):
    """Survey'den gelen ortam seçimini listeye çevir ve doğrula.

    AAP multiselect -> list gelir; CLI'dan -e ile 'TEST,PROD' string gelebilir.
    """
    if value is None:
        return []
    if isinstance(value, str):
        items = re.split(r"[,\n;]+", value)
    else:
        items = list(value)
    envs = []
    for item in items:
        env = _s(item).upper()
        if env and env not in envs:
            envs.append(env)
    invalid = [e for e in envs if e not in VALID_ENVS]
    if invalid:
        raise ValueError(
            "Geçersiz ortam: %s. İzin verilenler: %s" % (invalid, list(VALID_ENVS))
        )
    return envs


def mysqlinv_list(value):
    """Opsiyonel sunucu filtresi (virgül/satır ayrımlı) -> küçük harf liste."""
    if not value:
        return []
    if isinstance(value, str):
        value = re.split(r"[,\n;\s]+", value)
    return [_s(v).lower() for v in value if _s(v)]


def mysqlinv_normalize(rows, env_type_map, default_port=3316):
    """Ham satırları standart yapıya çevir.

    Dönen her kayıt:
      name, ip, port, fqdn, type_raw, environment, is_active, issues[]
    Bağlantı her zaman ListeningIP ile yapılır (farklı domainler/DNS bağımsız).
    'issues' boş değilse kayıt hedef olarak kullanılamaz (raporda skip).
    """
    lookup = {}
    for env, raw_values in (env_type_map or {}).items():
        for raw in raw_values or []:
            lookup[_s(raw).lower()] = _s(env).upper()

    out = []
    for row in rows or []:
        name = _s(row.get("ServerName"))
        ip = _s(row.get("ListeningIP"))
        fqdn = _s(row.get("Fqdn"))
        type_raw = _s(row.get("Type"))
        port_raw = _s(row.get("ListeningPort"))
        issues = []

        env = lookup.get(type_raw.lower(), "UNMAPPED")
        if env == "UNMAPPED":
            issues.append("Type '%s' hiçbir ortama eşlenmedi" % type_raw)

        if not ip:
            issues.append("ListeningIP boş (bağlantı IP ile yapılır)")

        if port_raw:
            if port_raw.isdigit() and 0 < int(port_raw) < 65536:
                port = int(port_raw)
            else:
                port = None
                issues.append("Geçersiz port '%s'" % port_raw)
        else:
            port = int(default_port)

        if not name:
            name = ip or "id-%s" % _s(row.get("id"))
            issues.append("ServerName boş")

        out.append({
            "id": row.get("id"),
            "name": name,
            "port": port,
            "ip": ip,
            "fqdn": fqdn,
            "type_raw": type_raw,
            "environment": env,
            "is_active": _truthy(row.get("isActive")),
            "issues": issues,
        })
    return out


def mysqlinv_select(records, environments, servers=None):
    """Seçilen ortam(lar) + opsiyonel sunucu filtresine göre ayır.

    Dönen: {'targets': [...], 'skipped': [{name, environment, reason}]}
    Sadece seçilen ortamlara ait (veya UNMAPPED) kayıtlar raporlanır;
    seçim dışı ortamlar sessizce elenir (rapor şişmesin).
    """
    envs = set(mysqlinv_envs(environments))
    server_filter = set(mysqlinv_list(servers))
    targets, skipped = [], []
    for rec in records or []:
        if server_filter and rec["name"].lower() not in server_filter:
            continue
        in_scope = rec["environment"] in envs
        if not in_scope and rec["environment"] != "UNMAPPED":
            continue
        if not rec.get("is_active", True):
            skipped.append(dict(name=rec["name"], environment=rec["environment"],
                                reason="isActive=0"))
        elif rec["issues"]:
            skipped.append(dict(name=rec["name"], environment=rec["environment"],
                                reason="; ".join(rec["issues"])))
        else:
            targets.append(rec)
    return {"targets": targets, "skipped": skipped}


def mysqlinv_count_by_env(records, environments):
    """Seçilen her ortam için hedef sayısı (0 olanlar dahil)."""
    counts = {env: 0 for env in mysqlinv_envs(environments)}
    for rec in records or []:
        if rec["environment"] in counts:
            counts[rec["environment"]] += 1
    return counts


class FilterModule(object):
    def filters(self):
        return {
            "mysqlinv_count_by_env": mysqlinv_count_by_env,
            "mysqlinv_envs": mysqlinv_envs,
            "mysqlinv_list": mysqlinv_list,
            "mysqlinv_normalize": mysqlinv_normalize,
            "mysqlinv_select": mysqlinv_select,
        }
