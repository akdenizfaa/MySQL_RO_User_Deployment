"""Faz 4 uygulama filtre testleri."""
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "roles", "mysql_user_apply", "filter_plugins"))
import mysqlapply as a  # noqa: E402

PLAN_ACCOUNTS = [
    {"account": "u@%", "statements": [
        {"kind": "CREATE_USER", "template": "CREATE USER 'u'@'%' IDENTIFIED WITH caching_sha2_password BY __TARGET_PASSWORD__",
         "masked": "CREATE USER 'u'@'%' IDENTIFIED WITH caching_sha2_password BY '********'"},
        {"kind": "GRANT", "template": "GRANT SELECT ON *.* TO 'u'@'%'", "masked": "GRANT SELECT ON *.* TO 'u'@'%'"}]},
    {"account": "u@10.%", "statements": [
        {"kind": "GRANT", "template": "GRANT SELECT ON *.* TO 'u'@'10.%'", "masked": "GRANT SELECT ON *.* TO 'u'@'10.%'"}]},
]


def test_plan_and_script_one_statement_per_line():
    plan = a.mysqlapply_plan(PLAN_ACCOUNTS)
    assert [p["account"] for p in plan] == ["u@%", "u@%", "u@10.%"]
    lines = a.mysqlapply_script(plan, "p'w").splitlines()
    assert len(lines) == 3 and lines[0].endswith("BY 'p\\'w';")
    assert all("__TARGET_PASSWORD__" not in l for l in lines)


def test_result_all_applied():
    plan = a.mysqlapply_plan(PLAN_ACCOUNTS)
    res = a.mysqlapply_result(plan, 0, "")
    assert [r["result"] for r in res] == ["APPLIED"] * 3
    assert a.mysqlapply_status(res) == "APPLIED"


def test_result_failure_at_line_2():
    plan = a.mysqlapply_plan(PLAN_ACCOUNTS)
    err = "ERROR 1410 (42000) at line 2: You are not allowed to create a user with GRANT"
    res = a.mysqlapply_result(plan, 1, err)
    assert [r["result"] for r in res] == ["APPLIED", "FAILED", "NOT_RUN"]
    assert res[1]["error"].startswith("ERROR 1410") and res[2]["error"] == ""
    assert a.mysqlapply_status(res) == "PARTIAL"


def test_result_failure_first_line_and_unknown():
    plan = a.mysqlapply_plan(PLAN_ACCOUNTS)
    res = a.mysqlapply_result(plan, 1, "ERROR 1819 (HY000) at line 1: Your password does not satisfy")
    assert a.mysqlapply_status(res) == "FAILED"
    res = a.mysqlapply_result(plan, 1, "mysql: command not found")
    assert set(r["result"] for r in res) == {"UNKNOWN"}
    assert a.mysqlapply_status([]) == "NO_CHANGE"
