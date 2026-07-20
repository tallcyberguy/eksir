"""
BM25-inspired sparse vectorizer for security alert text.

Produces Qdrant SparseVector objects from alert embed_text.
Tokens are mapped to integer indices via stable hashing (no vocabulary file needed).

Design choices for security alerts:
- IPs (e.g. 139.87.113.170) kept as single tokens — never split on dots
- CVE IDs (e.g. CVE-2021-44228) kept intact
- Rule name segments split on spaces, hyphens, underscores, dots
- Short tokens (<= 2 chars) discarded unless they are digits
- Common English stopwords removed
- Weights: TF × IDF_proxy where IDF_proxy = log(1 + token_length)
  (longer tokens are empirically rarer/more specific in alert text)
"""

import re
import math
import hashlib
from collections import Counter
from qdrant_client.models import SparseVector

# Sparse index size: 2^20 ≈ 1 million dimensions
# Collision probability is negligible for alert-sized vocabularies
_HASH_MOD = 2 ** 20

_STOPWORDS = {
    "the", "a", "an", "is", "in", "on", "at", "to", "for", "of",
    "and", "or", "from", "by", "with", "this", "that", "was", "are",
    "be", "been", "has", "have", "had", "not", "no", "as", "it", "its",
}

# Patterns matched in priority order (leftmost match wins)
_TOKEN_RE = re.compile(
    r"""
    \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}   # IPv4 address (keep whole)
    | CVE-\d{4}-\d+                         # CVE ID (keep whole)
    | [A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?  # general token
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _tokenize(text: str) -> list[str]:
    raw = _TOKEN_RE.findall(text)
    tokens = []
    for tok in raw:
        t = tok.lower()
        if t in _STOPWORDS:
            continue
        if len(t) <= 2 and not t.isdigit():
            continue
        tokens.append(t)
    return tokens


def _token_index(token: str) -> int:
    # Use MD5 for deterministic mapping — Python's hash() is randomized per process (PYTHONHASHSEED)
    digest = hashlib.md5(token.encode(), usedforsecurity=False).digest()
    return int.from_bytes(digest[:4], "little") % _HASH_MOD


def sparse_embed(text: str) -> SparseVector:
    """
    Convert text to a Qdrant SparseVector.
    Returns empty SparseVector for blank input.
    """
    if not text or not text.strip():
        return SparseVector(indices=[], values=[])

    tokens = _tokenize(text)
    if not tokens:
        return SparseVector(indices=[], values=[])

    tf = Counter(tokens)
    total = len(tokens)

    index_value: dict[int, float] = {}
    for token, count in tf.items():
        idx = _token_index(token)
        tf_score = count / total
        idf_proxy = math.log(1.0 + len(token))
        weight = tf_score * idf_proxy

        # Resolve hash collisions by keeping the higher weight
        if idx in index_value:
            index_value[idx] = max(index_value[idx], weight)
        else:
            index_value[idx] = weight

    indices = list(index_value.keys())
    values = [index_value[i] for i in indices]
    return SparseVector(indices=indices, values=values)
