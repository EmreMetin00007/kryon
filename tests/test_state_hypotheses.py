"""Durum hipotezleri: sınıf adı olmadan, yüzey şeklinden üretim."""
from __future__ import annotations

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "mcp-servers" / "mcp-reasoning"))

from cco_reasoning_core.hypotheses import generate_hypotheses  # noqa: E402

RECS = [
    {"url": "http://t/orders", "method": "GET", "path": "/orders",
     "params_json": '[{"name": "user_id"}]'},
    {"url": "http://t/orders/42", "method": "GET", "path": "/orders/42",
     "params_json": "[]"},
    {"url": "http://t/post/comment", "method": "POST", "path": "/post/comment",
     "params_json": '[{"name": "comment"}, {"name": "postId"}]'},
    {"url": "http://t/post", "method": "GET", "path": "/post",
     "params_json": '[{"name": "postId"}]'},
    {"url": "http://t/health", "method": "GET", "path": "/health", "params_json": "[]"},
]


def test_cross_identity_from_id_params():
    hyps = generate_hypotheses(RECS)
    kinds = {h["kind"] for h in hyps}
    assert "cross_identity_read" in kinds
    h = next(h for h in hyps if h["kind"] == "cross_identity_read")
    assert h["oracle"] == "validate_idor" and len(h["steps"]) == 2
    assert h["steps"][0]["actor"] == "A" and h["steps"][1]["actor"] == "B"


def test_write_then_read_from_path_kinship():
    hyps = generate_hypotheses(RECS)
    w = [h for h in hyps if h["kind"] == "write_then_read"]
    assert w and w[0]["oracle"] == "validate_stored_reflection"
    assert w[0]["write_surface"] == "/post/comment"


def test_plain_surface_yields_no_hypothesis():
    hyps = generate_hypotheses([RECS[-1]])
    assert hyps == []


COUPON_RECS = [
    {"url": "http://t/api/cart", "method": "GET", "path": "/api/cart",
     "params_json": '[{"name": "total"}, {"name": "status"}]'},
    {"url": "http://t/api/cart/coupon", "method": "POST", "path": "/api/cart/coupon",
     "params_json": '[{"name": "coupon"}, {"name": "discount"}]'},
    {"url": "http://t/api/cart/confirm", "method": "POST", "path": "/api/cart/confirm",
     "params_json": '[{"name": "status"}]'},
]


def test_single_use_replay_from_coupon_params():
    hyps = generate_hypotheses(COUPON_RECS)
    replay = [h for h in hyps if h["kind"] == "single_use_replay"]
    assert replay
    h = replay[0]
    assert h["oracle"] == "state_invariant"
    assert len(h["steps"]) == 5
    assert "coupon" in h["single_use_params"]


def test_numeric_surface_from_discount():
    hyps = generate_hypotheses(COUPON_RECS)
    nums = [h for h in hyps if h["kind"] == "numeric_surface"]
    assert nums and nums[0]["oracle"] == "state_invariant"
    assert "discount" in nums[0]["numeric_params"]


def test_state_transition_from_status():
    hyps = generate_hypotheses(COUPON_RECS)
    trans = [h for h in hyps if h["kind"] == "state_transition"]
    assert trans and trans[0]["oracle"] == "state_invariant"
    assert "status" in trans[0]["state_params"]


def test_registration_abuse_from_register_surface():
    recs = [
        {"url": "http://t/register", "method": "POST", "path": "/register",
         "params_json": '[{"name": "username"}, {"name": "email"}, {"name": "password"}]'},
        {"url": "http://t/cart", "method": "POST", "path": "/cart",
         "params_json": '[{"name": "productId"}, {"name": "quantity"}]'},
    ]
    hyps = generate_hypotheses(recs)
    reg = [h for h in hyps if h["kind"] == "registration_abuse"]
    assert len(reg) == 1
    assert reg[0]["write_surface"] == "/register"
    assert len(reg[0]["steps"]) == 3
    assert reg[0]["oracle"] == "state_invariant"


def test_cart_surface_yields_no_registration_abuse():
    hyps = generate_hypotheses(COUPON_RECS)
    assert [h for h in hyps if h["kind"] == "registration_abuse"] == []


def test_csrf_token_is_not_single_use():
    recs = [
        {"url": "http://t/login", "method": "POST", "path": "/login",
         "params_json": '[{"name": "csrf"}, {"name": "username"}]'},
    ]
    hyps = generate_hypotheses(recs)
    assert [h for h in hyps if h["kind"] == "single_use_replay"] == []


def test_no_class_names_required():
    # girdi bulgu sınıfı içermiyor; üretim yalnız şekilden
    assert generate_hypotheses(RECS)
