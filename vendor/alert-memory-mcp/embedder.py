"""
Embedding via local Ollama (nomic-embed-text).

Ollama must be running: `ollama serve`
Model must be pulled:   `ollama pull nomic-embed-text`

API endpoint: http://localhost:11434/api/embeddings
Output dim:   768 (nomic-embed-text)
"""

import requests
import time
from typing import Union

import os as _os
# Overridable via OLLAMA_URL env (see bge_embedder.py for context).
_OLLAMA_HOST = _os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_URL = f"{_OLLAMA_HOST}/api/embeddings"
_TAGS_URL  = f"{_OLLAMA_HOST}/api/tags"
MODEL = "nomic-embed-text"
EMBED_DIM = 768


class EmbedderError(Exception):
    pass


def embed(text: str, retries: int = 3) -> list[float]:
    """
    Embed a single text string.
    Returns a list of 768 floats.
    """
    if not text or not text.strip():
        raise EmbedderError("Cannot embed empty text")

    payload = {"model": MODEL, "prompt": text}

    for attempt in range(retries):
        try:
            resp = requests.post(OLLAMA_URL, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            vector = data.get("embedding")
            if not vector:
                raise EmbedderError(f"Ollama returned no embedding: {data}")
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
    """Check if Ollama is reachable and model is loaded."""
    try:
        resp = requests.get(_TAGS_URL, timeout=5)
        if resp.status_code != 200:
            return False
        models = [m["name"] for m in resp.json().get("models", [])]
        return any(MODEL in m for m in models)
    except requests.ConnectionError:
        return False


def check_or_raise():
    """Raise a clear error if Ollama isn't ready."""
    try:
        resp = requests.get(_TAGS_URL, timeout=5)
        models = [m["name"] for m in resp.json().get("models", [])]
        if not any(MODEL in m for m in models):
            raise EmbedderError(
                f"Model '{MODEL}' not found in Ollama.\n"
                f"Pull it with: ollama pull {MODEL}\n"
                f"Available models: {models}"
            )
    except requests.ConnectionError:
        raise EmbedderError(
            "Ollama is not running.\n"
            "Start with: ollama serve"
        )
