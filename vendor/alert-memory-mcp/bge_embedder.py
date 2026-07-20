"""
BGE-M3 embedding via local Ollama.

BGE-M3 (BAAI/bge-m3) is a multilingual, multi-granularity embedding model
that produces 1024-dimensional vectors. It outperforms nomic-embed-text on:
  - Multilingual content (Turkish + English alert text)
  - Long document retrieval (better for verbose PAN-OS / QRadar payloads)
  - Semantic accuracy on security terminology

Ollama model: bge-m3
Pull:  ollama pull bge-m3
Serve: ollama serve

API endpoint: http://localhost:11434/api/embeddings
Output dim:   1024 (bge-m3)

Used by:
  - store_v2.py  (alerts_v2 + iocs_v2 + knowledge_base_v2 collections)
  - migrate_to_bge_m3.py (one-time migration from nomic 768d → bge-m3 1024d)
"""

import os
import requests
import time
from typing import Union

# Overridable via OLLAMA_URL env so containerised consumers (e.g. ISOC) can
# point at host.docker.internal:11434 while local CLI use defaults to localhost.
_OLLAMA_HOST = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_URL = f"{_OLLAMA_HOST}/api/embeddings"
_TAGS_URL  = f"{_OLLAMA_HOST}/api/tags"
MODEL      = "bge-m3"
EMBED_DIM  = 1024


class EmbedderError(Exception):
    pass


def embed(text: str, retries: int = 3) -> list[float]:
    """
    Embed a single text string using BGE-M3.
    Returns a list of 1024 floats.
    """
    if not text or not text.strip():
        raise EmbedderError("Cannot embed empty text")

    payload = {"model": MODEL, "prompt": text}

    for attempt in range(retries):
        try:
            resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            vector = data.get("embedding")
            if not vector:
                raise EmbedderError(f"Ollama returned no embedding: {data}")
            if len(vector) != EMBED_DIM:
                raise EmbedderError(f"Unexpected dim {len(vector)}, expected {EMBED_DIM}")
            return vector
        except requests.ConnectionError:
            if attempt == retries - 1:
                raise EmbedderError(
                    "Cannot connect to Ollama. Is it running?\n"
                    "Start with: ollama serve"
                )
            time.sleep(1)
        except requests.HTTPError as e:
            raise EmbedderError(f"Ollama HTTP error: {e}")

    raise EmbedderError("Embedding failed after retries")


def embed_batch(texts: list[str]) -> list[list[float]]:
    """Embed multiple texts. Ollama doesn't support batching, so sequential."""
    return [embed(t) for t in texts]


def is_available() -> bool:
    """Check if Ollama is reachable and BGE-M3 model is loaded."""
    try:
        resp = requests.get(_TAGS_URL, timeout=5)
        if resp.status_code != 200:
            return False
        models = [m["name"] for m in resp.json().get("models", [])]
        return any(MODEL in m for m in models)
    except requests.ConnectionError:
        return False


def check_or_raise():
    """Raise a clear error if BGE-M3 isn't ready."""
    try:
        resp = requests.get(_TAGS_URL, timeout=5)
        models = [m["name"] for m in resp.json().get("models", [])]
        if not any(MODEL in m for m in models):
            raise EmbedderError(
                f"Model '{MODEL}' not found in Ollama.\n"
                f"Pull it with: ollama pull bge-m3\n"
                f"Available models: {models}"
            )
    except requests.ConnectionError:
        raise EmbedderError(
            "Ollama is not running.\n"
            "Start with: ollama serve"
        )


if __name__ == "__main__":
    check_or_raise()
    vec = embed("brute force attack failed login Windows Event 4625")
    print(f"BGE-M3 OK — dim={len(vec)}, first5={vec[:5]}")
