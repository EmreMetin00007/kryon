import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-hunter"))
from cco_hunter_core.loop import parse_suggested_fields, plan_graphql_operations

def test_graphql_operation_plan():
    text = ("🎯 Field suggestion enumeration sonuçları:\n"
        "  'userx' → user, users\n"
        "  'createx' → createUser, deleteOrder\n")
    fields = parse_suggested_fields(text)
    assert fields == ["user", "users", "createUser", "deleteOrder"], fields
    plan = {p["operation"]: p["tests"] for p in plan_graphql_operations(fields)}
    assert plan["createUser"] == ["authz_matrix", "mass_assignment"], plan
    assert plan["user"] == ["bola", "authz_matrix"], plan
    assert plan["users"] == ["bola", "authz_matrix"], plan
    print("FAZ5 HELPER OK")
