"""Unit testler: python3 -m pytest -q tests/"""
import json
import os
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "roles", "mysql_inventory", "filter_plugins"))
import mysqlinv as f  # noqa: E402

ENV_MAP = {"DEV": ["Dev"], "TEST": ["Test"], "QA": ["QA"], "PROD": ["Production"]}


@pytest.fixture
def rows():
    with open(os.path.join(HERE, "fixtures", "inventory_sample.json")) as fh:
        return json.load(fh)


def by_name(records):
    return {r["name"]: r for r in records}


def test_envs_accepts_list_and_string():
    assert f.mysqlinv_envs(["test", "PROD"]) == ["TEST", "PROD"]
    assert f.mysqlinv_envs("TEST, prod\nTEST") == ["TEST", "PROD"]


def test_envs_rejects_unknown():
    with pytest.raises(ValueError):
        f.mysqlinv_envs(["UAT"])


def test_normalize_mapping_and_issues(rows):
    recs = by_name(f.mysqlinv_normalize(rows, ENV_MAP))
    assert recs["gbarkt02"]["environment"] == "TEST"
    assert recs["gbarkt02"]["port"] == 3316
    assert recs["gbkmdp01"]["environment"] == "PROD"
    assert recs["roarkp02"]["ip"] == "192.168.100.52"
    assert recs["mockqa01"]["environment"] == "QA"
    assert recs["mockqa01"]["port"] is None                   # '33o6'
    assert recs["mockunk01"]["environment"] == "UNMAPPED"
    assert len(recs["mockunk01"]["issues"]) == 2              # type + IP boş


def test_case_insensitive_type_and_default_port(rows):
    recs = by_name(f.mysqlinv_normalize(rows, ENV_MAP))
    assert recs["mockdev01"]["environment"] == "DEV"          # 'dev' -> DEV
    assert recs["mockdev01"]["port"] == 3316                  # NULL port -> default


def test_ip_only_no_fqdn_fallback():
    recs = f.mysqlinv_normalize(
        [{"ServerName": "x", "ListeningIP": "", "Fqdn": "x.dom.tr", "Type": "Test",
          "ListeningPort": "3316", "isActive": 1}], ENV_MAP)
    assert recs[0]["issues"] == ["ListeningIP boş (bağlantı IP ile yapılır)"]


def test_select_prod_only(rows):
    sel = f.mysqlinv_select(f.mysqlinv_normalize(rows, ENV_MAP), ["PROD"])
    assert sorted(t["name"] for t in sel["targets"]) == ["gbapgp01", "gbarkap03", "gbkmdp01", "roarkp02"]
    # UNMAPPED her zaman raporlanır, TEST kayıtları raporlanmaz
    assert [s["name"] for s in sel["skipped"]] == ["mockunk01"]


def test_select_test_reports_inactive(rows):
    sel = f.mysqlinv_select(f.mysqlinv_normalize(rows, ENV_MAP), "TEST")
    assert sorted(t["name"] for t in sel["targets"]) == ["gbapgaq01", "gbarkt02"]
    reasons = {s["name"]: s["reason"] for s in sel["skipped"]}
    assert reasons["gbwspt02"] == "isActive=0"
    assert reasons["gbwspq01"] == "isActive=0"


def test_select_server_filter(rows):
    sel = f.mysqlinv_select(f.mysqlinv_normalize(rows, ENV_MAP), ["TEST", "PROD"], "GBARKT02")
    assert [t["name"] for t in sel["targets"]] == ["gbarkt02"]
    assert sel["skipped"] == []


def test_count_by_env(rows):
    sel = f.mysqlinv_select(f.mysqlinv_normalize(rows, ENV_MAP), ["TEST", "QA"])
    assert f.mysqlinv_count_by_env(sel["targets"], ["TEST", "QA"]) == {"TEST": 2, "QA": 0}
