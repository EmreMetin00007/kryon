"""Pure JavaScript route composition, parser, source map, and client logic mapping."""
from __future__ import annotations

from .client_logic import build_client_logic_map
from .compose import compose_js_routes
from .opacity import assess_js_opacity
from .parsers import parse_javascript
from .sourcemap import parse_source_map

__all__ = [
    "assess_js_opacity",
    "build_client_logic_map",
    "compose_js_routes",
    "parse_javascript",
    "parse_source_map",
]
