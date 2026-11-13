"""cco_postex_core — post-exploitation saf parser ve kural setleri.

Ag bagimliligi yok, dosya/ortam okumaz; deterministik ve test edilebilir.
Hassas degerler (parola/hash) evidence'a maskelenmis girer; ham secret
ASLA dondurulmez — credential adaylari vault'a ayri akiskan yazilir.
"""

from .parsers import parse_linpeas, parse_winpeas

__all__ = ["parse_linpeas", "parse_winpeas"]
