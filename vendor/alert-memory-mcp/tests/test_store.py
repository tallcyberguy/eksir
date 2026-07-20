"""
Integration test: parse → embed → index → search

Requires:
  - ollama serve         (with nomic-embed-text pulled)
  - qdrant running       (docker run -d --name qdrant -p 6333:6333 qdrant/qdrant)

Run: python3 tests/test_store.py
"""

import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import embedder
import parsers
from store import AlertStore

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(filename):
    with open(os.path.join(FIXTURES, filename)) as f:
        return f.read()


def main():
    print("=== Checking Ollama ===")
    embedder.check_or_raise()
    print(f"  Ollama OK — model: {embedder.MODEL}")

    print("\n=== Connecting to Qdrant ===")
    store = AlertStore()
    print("  Qdrant OK")

    # Parse all three sample alerts
    alerts = [
        parsers.parse(load("qradar_sample.txt"),                         customer="contoso"),
        parsers.parse(json.loads(load("wazuh_suricata_sample.json")),    customer="fabrikam"),
        parsers.parse(json.loads(load("wazuh_winevent_sample.json")),    customer="fabrikam"),
    ]

    print(f"\n=== Indexing {len(alerts)} alerts ===")
    for a in alerts:
        aid = store.index_alert(a)
        print(f"  [{a.source_product}] {a.threat_category:12s} | {a.rule_name[:55]}...")
        print(f"           alert_id={aid}")

    # Similarity search — new brute force alert, should match winevent
    print("\n=== Similarity Search (brute_force) ===")
    from normalizer import NormalizedAlert
    query = NormalizedAlert(
        rule_name="Multiple NTLM logon failures",
        threat_category="brute_force",
        src_ip="10.10.10.50",
        dst_ip="192.168.30.4",
        mitre_technique="T1110",
        mitre_tactic="Credential Access",
        severity=12,
    ).finalize()

    results = store.search_similar(query, top_k=3)
    for r in results:
        print(f"  score={r['score']} | {r['threat_category']:12s} | {r['rule_name'][:50]}")
        print(f"    customer={r['customer']} | verdict={r['verdict']}")

    # Save a verdict and re-search
    print("\n=== Saving Verdict (FP) ===")
    winevent_id = alerts[2].alert_id
    store.save_verdict(
        alert_id=winevent_id,
        verdict="FP",
        reason="Expired password (SubStatus 0xC0000071) — mapped drive retry",
        analyst="analyst01"
    )
    print(f"  Verdict saved for alert_id={winevent_id}")

    # Re-search — verdict should now appear in results
    print("\n=== Re-search after verdict ===")
    results2 = store.search_similar(query, top_k=3)
    for r in results2:
        verdict_str = f"{r['verdict']} ({r['verdict_reason']})" if r['verdict'] else "none"
        print(f"  score={r['score']} | verdict={verdict_str}")

    # Stats
    print("\n=== Stats ===")
    s = store.stats()
    print(f"  Total indexed: {s['total_alerts']}")
    print(f"  Collection:    {s['collection']}")
    print(f"  Embed dim:     {s['embed_dim']}")

    print("\n=== All integration tests passed ===")


if __name__ == "__main__":
    main()
