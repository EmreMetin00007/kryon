"""SPA kapsama laboratuvarı: doğruluk listesi ve puanlayıcı birim testleri."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "lab"))
import spa_lab  # noqa: E402


def test_spa_truth_is_self_consistent():
    truth = spa_lab.build_truth()
    assert len(truth) == 13
    keys = {(row["method"], row["path"]) for row in truth}
    assert len(keys) == len(truth)


def test_score_surface_counts_routes_params_and_extras():
    rows = [
        {"method": "GET", "url": "http://x/api/search?q=1", "params": [
            {"name": "q"}, {"name": "sort"}]},
        {"method": "POST", "url": "http://x/api/notes", "params": [{"name": "title"}]},
        {"method": "GET", "url": "http://x/api/unknown", "params": []},
    ]
    result = spa_lab.score_surface(spa_lab.build_truth(), rows)
    assert result["routes_found"] == 2
    assert result["params_found"] == 3  # q, sort, title (body eksik)
    assert "POST /api/notes" not in result["missed"]
    assert result["extra_routes"] == ["GET /api/unknown"]


def test_score_surface_matches_template_segments():
    rows = [{"method": "PUT", "url": "http://x/api/orders/{orderId}",
             "params": [{"name": "orderId"}, {"name": "total"}]}]
    result = spa_lab.score_surface(spa_lab.build_truth(), rows)
    assert "PUT /api/orders/{orderId}" not in result["missed"]
    assert result["params_found"] == 2
