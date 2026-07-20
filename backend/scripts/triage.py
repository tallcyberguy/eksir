#!/usr/bin/env python3
"""
Malware Triage - Multi-source threat intelligence lookup.

API keys can be configured via:
1. Config file: ~/.config/malware-triage/config.json
2. Environment variables: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
3. Command line: --vt-key, --abuseipdb-key
"""

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# OTX integration — import OTXClient if otx_lookup.py is in the same directory
try:
    sys.path.insert(0, str(Path(__file__).parent))
    from otx_lookup import OTXClient

    _OTX_AVAILABLE = True
except ImportError:
    _OTX_AVAILABLE = False

# Optional WHOIS library
try:
    import whois as pywhois

    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

# Check for requests library
try:
    import requests
except ImportError:
    print(
        "Error: requests library required. Install with: pip install requests --break-system-packages"
    )
    sys.exit(1)


class Colors:
    """ANSI terminal colors. Call Colors.disable() when writing to files or non-TTY output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def disable(cls):
        cls.RESET = cls.BOLD = cls.DIM = ""
        cls.RED = cls.YELLOW = cls.GREEN = cls.CYAN = cls.WHITE = ""

    @classmethod
    def verdict(cls, v: str) -> str:
        """Return verdict string wrapped in appropriate color."""
        mapping = {
            "malicious": f"{cls.BOLD}{cls.RED}{v.upper()}{cls.RESET}",
            "suspicious": f"{cls.BOLD}{cls.YELLOW}{v.upper()}{cls.RESET}",
            "clean_or_unknown": f"{cls.GREEN}{v.upper()}{cls.RESET}",
            "unknown": f"{cls.DIM}{v.upper()}{cls.RESET}",
        }
        return mapping.get(v, v.upper())

    @classmethod
    def section(cls, name: str) -> str:
        return f"{cls.BOLD}{cls.CYAN}{name}{cls.RESET}"

    @classmethod
    def bold(cls, text: str) -> str:
        return f"{cls.BOLD}{text}{cls.RESET}"

    @classmethod
    def warn(cls, text: str) -> str:
        return f"{cls.BOLD}{cls.YELLOW}{text}{cls.RESET}"

    @classmethod
    def danger(cls, text: str) -> str:
        return f"{cls.BOLD}{cls.RED}{text}{cls.RESET}"

    @classmethod
    def ok(cls, text: str) -> str:
        return f"{cls.GREEN}{text}{cls.RESET}"

    @classmethod
    def dim(cls, text: str) -> str:
        return f"{cls.DIM}{text}{cls.RESET}"


def load_config() -> dict:
    """
    Load API keys from config file.

    Config file locations (in order of priority):
    1. Skill's own config directory (bundled with skill)
    2. /mnt/user-data/uploads/config.json (Claude Desktop uploads)
    3. ~/.config/malware-triage/config.json
    4. ./config.json (current directory)
    """
    # Get the skill's directory (parent of scripts/)
    script_dir = Path(__file__).parent
    skill_dir = script_dir.parent

    config_paths = [
        # Bundled with skill
        skill_dir / "config" / "config.json",
        skill_dir / "config" / "api_keys.json",
        skill_dir / "config.json",
        # Claude Desktop uploads
        Path("/mnt/user-data/uploads/config.json"),
        Path("/mnt/user-data/uploads/api_keys.json"),
        # User home config
        Path.home() / ".config" / "malware-triage" / "config.json",
        Path.home() / ".malware-triage.json",
        # Current directory
        Path("config.json"),
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = json.load(f)
                    print(f"[*] Loaded config from: {config_path}", file=sys.stderr)
                    return config
            except (OSError, json.JSONDecodeError) as e:
                print(f"[!] Failed to load {config_path}: {e}", file=sys.stderr)
                continue

    return {}


def get_api_key(key_name: str, cli_value: str | None = None) -> str | None:
    """
    Get API key from multiple sources (priority order):
    1. Command line argument
    2. Environment variable
    3. Config file
    """
    # CLI takes priority
    if cli_value:
        return cli_value

    # Then environment variable
    env_key = os.environ.get(key_name)
    if env_key:
        return env_key

    # Finally config file
    config = load_config()
    config_key_map = {
        "VIRUSTOTAL_API_KEY": ["virustotal_api_key", "vt_api_key", "virustotal"],
        "ABUSEIPDB_API_KEY": ["abuseipdb_api_key", "abuseipdb"],
        "ABUSECH_AUTH_KEY": [
            "abusech_auth_key",
            "abuse_ch_auth_key",
            "malwarebazaar_auth_key",
            "auth_key",
        ],
        "OTX_API_KEY": ["otx_api_key", "alienvault_otx_key", "otx_key"],
    }

    possible_keys = config_key_map.get(key_name, [key_name.lower()])

    for config_key in possible_keys:
        if config_key in config:
            return config[config_key]

    return None


def create_default_config():
    """Create a default config file template."""
    config_dir = Path.home() / ".config" / "malware-triage"
    config_path = config_dir / "config.json"

    if config_path.exists():
        print(f"Config already exists: {config_path}")
        return

    config_dir.mkdir(parents=True, exist_ok=True)

    default_config = {
        "abusech_auth_key": "YOUR_ABUSECH_AUTH_KEY_HERE",
        "virustotal_api_key": "YOUR_VT_API_KEY_HERE",
        "abuseipdb_api_key": "YOUR_ABUSEIPDB_API_KEY_HERE",
        "otx_api_key": "YOUR_OTX_API_KEY_HERE",
    }

    with open(config_path, "w") as f:
        json.dump(default_config, f, indent=2)

    print(f"Created config file: {config_path}")
    print("Edit this file with your API keys.")
    print()
    print("Get your keys from:")
    print("  - abuse.ch (MalwareBazaar/ThreatFox): https://auth.abuse.ch/")
    print("  - VirusTotal: https://www.virustotal.com/gui/my-apikey")
    print("  - AbuseIPDB: https://www.abuseipdb.com/account/api")


class ThreatIntelClient:
    """Base class for threat intel API clients."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "MalwareTriage/1.0 (Threat Intelligence Lookup Tool)",
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )

    def _safe_request(self, method: str, url: str, **kwargs) -> dict | None:
        """Make a request with error handling."""
        try:
            resp = self.session.request(method, url, timeout=30, **kwargs)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"error": "not_found", "status": 404}
            elif resp.status_code == 429:
                return {"error": "rate_limited", "status": 429}
            elif resp.status_code == 401:
                return {"error": "unauthorized", "status": 401, "detail": resp.text[:200]}
            else:
                return {
                    "error": f"http_{resp.status_code}",
                    "status": resp.status_code,
                    "detail": resp.text[:200],
                }
        except requests.exceptions.Timeout:
            return {"error": "timeout"}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
        except json.JSONDecodeError:
            return {"error": "invalid_json"}


class MalwareBazaar(ThreatIntelClient):
    """MalwareBazaar API client (abuse.ch) - Requires Auth-Key."""

    BASE_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, auth_key: str | None = None):
        super().__init__()
        self.auth_key = auth_key
        if self.auth_key:
            self.session.headers.update({"Auth-Key": self.auth_key})

    def _is_configured(self) -> bool:
        return bool(self.auth_key)

    def query_hash(self, hash_value: str) -> dict:
        """Query MalwareBazaar for a file hash."""
        if not self._is_configured():
            return {"source": "malwarebazaar", "found": False, "error": "no_auth_key"}

        data = {"query": "get_info", "hash": hash_value}
        result = self._safe_request("POST", self.BASE_URL, data=data)

        if not result or "error" in result:
            return {
                "source": "malwarebazaar",
                "found": False,
                "error": result.get("error") if result else "request_failed",
                "detail": result.get("detail") if result else None,
            }

        if result.get("query_status") == "hash_not_found":
            return {"source": "malwarebazaar", "found": False}

        if result.get("query_status") == "ok" and result.get("data"):
            sample = result["data"][0]
            return {
                "source": "malwarebazaar",
                "found": True,
                "sha256": sample.get("sha256_hash"),
                "sha1": sample.get("sha1_hash"),
                "md5": sample.get("md5_hash"),
                "file_name": sample.get("file_name"),
                "file_type": sample.get("file_type"),
                "file_size": sample.get("file_size"),
                "signature": sample.get("signature"),  # Malware family
                "first_seen": sample.get("first_seen"),
                "last_seen": sample.get("last_seen"),
                "tags": sample.get("tags", []),
                "intelligence": sample.get("intelligence", {}),
                "delivery_method": sample.get("delivery_method"),
                "comment": sample.get("comment"),
                "reporter": sample.get("reporter"),
                "yara_rules": sample.get("yara_rules", []),
                "vendor_intel": sample.get("vendor_intel", {}),
            }

        return {"source": "malwarebazaar", "found": False, "raw_status": result.get("query_status")}

    def query_tag(self, tag: str, limit: int = 10) -> dict:
        """Query MalwareBazaar for samples by tag (e.g., malware family)."""
        if not self._is_configured():
            return {"source": "malwarebazaar", "found": False, "error": "no_auth_key"}

        data = {"query": "get_taginfo", "tag": tag, "limit": limit}
        result = self._safe_request("POST", self.BASE_URL, data=data)

        if not result or "error" in result:
            return {"source": "malwarebazaar", "found": False}

        if result.get("query_status") == "ok" and result.get("data"):
            samples = []
            for sample in result["data"][:limit]:
                samples.append(
                    {
                        "sha256": sample.get("sha256_hash"),
                        "file_name": sample.get("file_name"),
                        "signature": sample.get("signature"),
                        "first_seen": sample.get("first_seen"),
                    }
                )
            return {
                "source": "malwarebazaar",
                "found": True,
                "tag": tag,
                "samples": samples,
                "count": len(samples),
            }

        return {"source": "malwarebazaar", "found": False}


class ThreatFox(ThreatIntelClient):
    """ThreatFox API client (abuse.ch) - Requires Auth-Key."""

    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, auth_key: str | None = None):
        super().__init__()
        self.auth_key = auth_key
        if self.auth_key:
            self.session.headers.update({"Auth-Key": self.auth_key})

    def _is_configured(self) -> bool:
        return bool(self.auth_key)

    def query_ioc(self, ioc: str) -> dict:
        """Query ThreatFox for an IOC (hash, IP, domain, URL)."""
        if not self._is_configured():
            return {"source": "threatfox", "found": False, "error": "no_auth_key"}

        data = {"query": "search_ioc", "search_term": ioc}
        result = self._safe_request("POST", self.BASE_URL, data=data)

        if not result or "error" in result:
            return {
                "source": "threatfox",
                "found": False,
                "error": result.get("error") if result else "request_failed",
                "detail": result.get("detail") if result else None,
            }

        if result.get("query_status") == "no_result":
            return {"source": "threatfox", "found": False}

        if result.get("query_status") == "ok" and result.get("data"):
            iocs = []
            for entry in result["data"]:
                iocs.append(
                    {
                        "ioc": entry.get("ioc"),
                        "ioc_type": entry.get("ioc_type"),
                        "threat_type": entry.get("threat_type"),
                        "malware": entry.get("malware"),
                        "malware_alias": entry.get("malware_alias"),
                        "malware_malpedia": entry.get("malware_malpedia"),
                        "confidence": entry.get("confidence_level"),
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("last_seen"),
                        "reporter": entry.get("reporter"),
                        "tags": entry.get("tags", []),
                    }
                )
            return {"source": "threatfox", "found": True, "iocs": iocs, "count": len(iocs)}

        return {"source": "threatfox", "found": False}

    def query_malware(self, malware_name: str, limit: int = 10) -> dict:
        """Query ThreatFox for IOCs associated with a malware family."""
        if not self._is_configured():
            return {"source": "threatfox", "found": False, "error": "no_auth_key"}

        data = {"query": "malwareinfo", "malware": malware_name}
        result = self._safe_request("POST", self.BASE_URL, data=data)

        if not result or "error" in result:
            return {"source": "threatfox", "found": False}

        if result.get("query_status") == "ok" and result.get("data"):
            return {
                "source": "threatfox",
                "found": True,
                "malware": malware_name,
                "ioc_count": len(result["data"]),
                "sample_iocs": result["data"][:limit],
            }

        return {"source": "threatfox", "found": False}


class URLhaus(ThreatIntelClient):
    """URLhaus API client (abuse.ch) - Auth-Key optional but recommended."""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1/"

    def __init__(self, auth_key: str | None = None):
        super().__init__()
        self.auth_key = auth_key
        if self.auth_key:
            self.session.headers.update({"Auth-Key": self.auth_key})

    def query_url(self, url: str) -> dict:
        """Query URLhaus for a URL."""
        data = {"url": url}
        result = self._safe_request("POST", f"{self.BASE_URL}url/", data=data)

        if not result or "error" in result:
            return {
                "source": "urlhaus",
                "found": False,
                "error": result.get("error") if result else "request_failed",
            }

        if result.get("query_status") == "no_results":
            return {"source": "urlhaus", "found": False}

        if result.get("query_status") == "ok":
            return {
                "source": "urlhaus",
                "found": True,
                "url": result.get("url"),
                "url_status": result.get("url_status"),  # online/offline
                "threat": result.get("threat"),
                "tags": result.get("tags", []),
                "host": result.get("host"),
                "date_added": result.get("date_added"),
                "last_online": result.get("last_online"),
                "takedown_time_seconds": result.get("takedown_time_seconds"),
                "payloads": result.get("payloads", []),
            }

        return {"source": "urlhaus", "found": False}

    def query_host(self, host: str) -> dict:
        """Query URLhaus for a domain or IP."""
        data = {"host": host}
        result = self._safe_request("POST", f"{self.BASE_URL}host/", data=data)

        if not result or "error" in result:
            return {
                "source": "urlhaus",
                "found": False,
                "error": result.get("error") if result else "request_failed",
            }

        if result.get("query_status") == "no_results":
            return {"source": "urlhaus", "found": False}

        if result.get("query_status") == "ok":
            return {
                "source": "urlhaus",
                "found": True,
                "host": result.get("host"),
                "firstseen": result.get("firstseen"),
                "url_count": result.get("url_count"),
                "urls": result.get("urls", [])[:10],  # Limit URLs returned
            }

        return {"source": "urlhaus", "found": False}

    def query_hash(self, hash_value: str) -> dict:
        """Query URLhaus for a payload hash."""
        hash_type = "sha256_hash" if len(hash_value) == 64 else "md5_hash"
        data = {hash_type: hash_value}
        result = self._safe_request("POST", f"{self.BASE_URL}payload/", data=data)

        if not result or "error" in result:
            return {"source": "urlhaus", "found": False}

        if result.get("query_status") == "no_results":
            return {"source": "urlhaus", "found": False}

        if result.get("query_status") == "ok":
            return {
                "source": "urlhaus",
                "found": True,
                "md5": result.get("md5_hash"),
                "sha256": result.get("sha256_hash"),
                "file_type": result.get("file_type"),
                "file_size": result.get("file_size"),
                "signature": result.get("signature"),
                "firstseen": result.get("firstseen"),
                "lastseen": result.get("lastseen"),
                "download_count": result.get("url_count"),
                "urls": result.get("urls", [])[:10],
            }

        return {"source": "urlhaus", "found": False}


class VirusTotal(ThreatIntelClient):
    """VirusTotal API client - Requires API key."""

    BASE_URL = "https://www.virustotal.com/api/v3/"

    def __init__(self, api_key: str | None = None):
        super().__init__(api_key)
        if self.api_key:
            self.session.headers.update({"x-apikey": self.api_key})

    def _is_configured(self) -> bool:
        return bool(self.api_key)

    def query_hash(self, hash_value: str) -> dict:
        """Query VirusTotal for a file hash."""
        if not self._is_configured():
            return {"source": "virustotal", "found": False, "error": "no_api_key"}

        result = self._safe_request("GET", f"{self.BASE_URL}files/{hash_value}")

        if not result or "error" in result:
            error = result.get("error") if result else "request_failed"
            if error == "not_found":
                return {"source": "virustotal", "found": False}
            return {"source": "virustotal", "found": False, "error": error}

        if "data" in result:
            attrs = result["data"].get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            file_result = {
                "source": "virustotal",
                "found": True,
                "sha256": attrs.get("sha256"),
                "sha1": attrs.get("sha1"),
                "md5": attrs.get("md5"),
                "file_name": attrs.get("meaningful_name") or attrs.get("names", ["unknown"])[0]
                if attrs.get("names")
                else "unknown",
                "file_type": attrs.get("type_description"),
                "file_size": attrs.get("size"),
                "magic": attrs.get("magic"),
                "detections": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()) if stats else 0,
                },
                "detection_rate": f"{stats.get('malicious', 0)}/{sum(stats.values())}"
                if stats
                else "0/0",
                "popular_threat_names": attrs.get("popular_threat_classification", {}).get(
                    "suggested_threat_label"
                ),
                "tags": attrs.get("tags", []),
                "first_submission": attrs.get("first_submission_date"),
                "last_analysis": attrs.get("last_analysis_date"),
                "reputation": attrs.get("reputation"),
                "signature_info": attrs.get("signature_info"),
                "sandbox_verdicts": attrs.get("sandbox_verdicts", {}),
                "last_analysis_results": attrs.get("last_analysis_results", {}),
            }
            # Fetch behaviour summary (second API call — chained on sha256)
            sha256_val = attrs.get("sha256")
            if sha256_val:
                time.sleep(0.3)  # Small buffer between two calls to the same API
                file_result["behaviour_summary"] = self.get_behaviour_summary(sha256_val)
            return file_result

        return {"source": "virustotal", "found": False}

    def get_behaviour_summary(self, sha256: str) -> dict:
        """
        Fetch VT sandbox behaviour summary — DNS lookups, network connections,
        HTTP conversations, file drops, processes. Requires a second API call
        after the main file lookup (chained on sha256).
        """
        if not self._is_configured():
            return {}
        result = self._safe_request("GET", f"{self.BASE_URL}files/{sha256}/behaviour_summary")
        if not result or "error" in result:
            return {}
        data = result.get("data", {})

        def _trim(lst, n=15):
            return lst[:n] if isinstance(lst, list) else []

        return {
            "dns_lookups": _trim(data.get("dns_lookups", []), 20),
            "ip_traffic": _trim(data.get("ip_traffic", []), 20),
            "http_conversations": _trim(data.get("http_conversations", []), 10),
            "files_written": _trim(data.get("files_written", []), 10),
            "files_opened": _trim(data.get("files_opened", []), 10),
            "processes_created": _trim(data.get("processes_created", []), 10),
            "registry_keys_set": _trim(data.get("registry_keys_set", []), 10),
            "tags": data.get("tags", []),
        }

    def get_ip_resolutions(self, ip: str, limit: int = 10) -> list:
        """Query VirusTotal passive DNS resolutions for an IP (hostnames that pointed to it)."""
        if not self._is_configured():
            return []
        result = self._safe_request(
            "GET", f"{self.BASE_URL}ip_addresses/{ip}/resolutions", params={"limit": limit}
        )
        if not result or "error" in result:
            return []
        return [
            {
                "hostname": item.get("attributes", {}).get("host_name", ""),
                "last_resolved": datetime.fromtimestamp(
                    item["attributes"]["date"], tz=timezone.utc
                ).strftime("%Y-%m-%d")
                if item.get("attributes", {}).get("date")
                else None,
            }
            for item in result.get("data", [])
            if item.get("attributes", {}).get("host_name")
        ]

    def query_ip(self, ip: str) -> dict:
        """Query VirusTotal for an IP address."""
        if not self._is_configured():
            return {"source": "virustotal", "found": False, "error": "no_api_key"}

        result = self._safe_request("GET", f"{self.BASE_URL}ip_addresses/{ip}")

        if not result or "error" in result:
            return {
                "source": "virustotal",
                "found": False,
                "error": result.get("error") if result else "request_failed",
            }

        if "data" in result:
            attrs = result["data"].get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            time.sleep(0.3)
            resolutions = self.get_ip_resolutions(ip)

            return {
                "source": "virustotal",
                "found": True,
                "ip": ip,
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
                "reputation": attrs.get("reputation"),
                "detections": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                },
                "tags": attrs.get("tags", []),
                "last_analysis": attrs.get("last_analysis_date"),
                "resolutions": resolutions,
            }

        return {"source": "virustotal", "found": False}

    def query_domain(self, domain: str) -> dict:
        """Query VirusTotal for a domain."""
        if not self._is_configured():
            return {"source": "virustotal", "found": False, "error": "no_api_key"}

        result = self._safe_request("GET", f"{self.BASE_URL}domains/{domain}")

        if not result or "error" in result:
            return {
                "source": "virustotal",
                "found": False,
                "error": result.get("error") if result else "request_failed",
            }

        if "data" in result:
            attrs = result["data"].get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            return {
                "source": "virustotal",
                "found": True,
                "domain": domain,
                "registrar": attrs.get("registrar"),
                "creation_date": attrs.get("creation_date"),
                "reputation": attrs.get("reputation"),
                "detections": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                },
                "categories": attrs.get("categories", {}),
                "tags": attrs.get("tags", []),
                "last_analysis": attrs.get("last_analysis_date"),
            }

        return {"source": "virustotal", "found": False}

    def query_url(self, url: str) -> dict:
        """Query VirusTotal for a URL using its base64url ID."""
        if not self._is_configured():
            return {"source": "virustotal", "found": False, "error": "no_api_key"}

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        result = self._safe_request("GET", f"{self.BASE_URL}urls/{url_id}")

        if not result or result.get("error") == "not_found":
            return {"source": "virustotal", "found": False}

        if "error" in result:
            return {"source": "virustotal", "found": False, "error": result["error"]}

        if "data" in result:
            attrs = result["data"].get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            return {
                "source": "virustotal",
                "found": malicious > 0,
                "url": attrs.get("url", url),
                "final_url": attrs.get("last_final_url"),
                "detections": {
                    "malicious": malicious,
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "total": total,
                },
                "detection_rate": f"{malicious}/{total}",
                "threat_names": attrs.get("threat_names", []),
                "categories": attrs.get("categories", {}),
                "last_analysis": attrs.get("last_analysis_date"),
                "title": attrs.get("title"),
            }

        return {"source": "virustotal", "found": False}


class AbuseIPDB(ThreatIntelClient):
    """AbuseIPDB API client - Requires API key."""

    BASE_URL = "https://api.abuseipdb.com/api/v2/"

    def __init__(self, api_key: str | None = None):
        super().__init__(api_key)
        if self.api_key:
            self.session.headers.update({"Key": self.api_key, "Accept": "application/json"})

    def _is_configured(self) -> bool:
        return bool(self.api_key)

    def query_ip(self, ip: str) -> dict:
        """Query AbuseIPDB for an IP address."""
        if not self._is_configured():
            return {"source": "abuseipdb", "found": False, "error": "no_api_key"}

        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        result = self._safe_request("GET", f"{self.BASE_URL}check", params=params)

        if not result or "error" in result:
            return {
                "source": "abuseipdb",
                "found": False,
                "error": result.get("error") if result else "request_failed",
            }

        if "data" in result:
            data = result["data"]
            return {
                "source": "abuseipdb",
                "found": True,
                "ip": data.get("ipAddress"),
                "is_public": data.get("isPublic"),
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
                "is_tor": data.get("isTor"),
                "is_whitelisted": data.get("isWhitelisted"),
                "total_reports": data.get("totalReports"),
                "num_distinct_users": data.get("numDistinctUsers"),
                "last_reported": data.get("lastReportedAt"),
            }

        return {"source": "abuseipdb", "found": False}


# IOC type detection
def detect_ioc_type(ioc: str) -> str:
    """Detect the type of IOC."""
    ioc = ioc.strip()

    # Hash detection
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "md5"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "sha256"

    # URL detection
    if re.match(r"^https?://", ioc, re.IGNORECASE):
        return "url"

    # IP detection
    if re.match(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
        ioc,
    ):
        return "ipv4"

    # Domain detection (simple)
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", ioc):
        return "domain"

    return "unknown"


def query_whois_domain(domain: str) -> dict:
    """Query WHOIS for domain registration info. Requires: pip install python-whois"""
    if not _WHOIS_AVAILABLE:
        return {
            "source": "whois",
            "found": False,
            "error": "python-whois not installed. Run: pip install python-whois --break-system-packages",
        }

    try:
        w = pywhois.whois(domain)

        # creation_date can be a list or a single datetime
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]

        age_days = None
        new_domain = False
        if creation:
            try:
                cd = creation.replace(tzinfo=None) if hasattr(creation, "replace") else None
                if cd:
                    age_days = (datetime.now() - cd).days
                    new_domain = age_days < 30
            except Exception:
                pass

        nameservers = []
        if w.name_servers:
            nameservers = sorted({ns.lower().rstrip(".") for ns in w.name_servers})[:4]

        return {
            "source": "whois",
            "found": True,
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": creation.isoformat()
            if hasattr(creation, "isoformat")
            else str(creation)
            if creation
            else None,
            "expiration_date": expiry.isoformat()
            if hasattr(expiry, "isoformat")
            else str(expiry)
            if expiry
            else None,
            "age_days": age_days,
            "new_domain": new_domain,
            "nameservers": nameservers,
        }
    except Exception as e:
        return {"source": "whois", "found": False, "error": str(e)}


def calculate_file_hashes(filepath: str) -> dict:
    """Calculate hashes for a file."""
    path = Path(filepath)
    if not path.exists():
        return {"error": f"File not found: {filepath}"}

    data = path.read_bytes()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


class _TTLCache:
    """In-memory TTL cache. Avoids redundant API calls for the same IOC within a session."""

    def __init__(self, ttl_seconds: int = 300):
        self._store: dict = {}
        self._ttl = ttl_seconds

    def get(self, key: str):
        if key in self._store:
            val, ts = self._store[key]
            if time.time() - ts < self._ttl:
                return val
            del self._store[key]
        return None

    def set(self, key: str, value):
        self._store[key] = (value, time.time())

    def clear(self):
        self._store.clear()


_SESSION_CACHE = _TTLCache(ttl_seconds=300)


class MalwareTriage:
    """Main triage orchestrator."""

    def __init__(
        self,
        vt_key: str | None = None,
        abuseipdb_key: str | None = None,
        abusech_key: str | None = None,
        otx_key: str | None = None,
        verbose: bool = True,
    ):
        # Get API keys from multiple sources
        vt_api_key = get_api_key("VIRUSTOTAL_API_KEY", vt_key)
        abuseipdb_api_key = get_api_key("ABUSEIPDB_API_KEY", abuseipdb_key)
        abusech_auth_key = get_api_key("ABUSECH_AUTH_KEY", abusech_key)
        otx_api_key = get_api_key("OTX_API_KEY", otx_key)

        if verbose:
            if abusech_auth_key:
                print(
                    f"[*] abuse.ch Auth-Key loaded (ends with ...{abusech_auth_key[-4:]})",
                    file=sys.stderr,
                )
            else:
                print(
                    "[!] abuse.ch Auth-Key NOT found (MalwareBazaar/ThreatFox will fail)",
                    file=sys.stderr,
                )

            if vt_api_key:
                print(
                    f"[*] VirusTotal API key loaded (ends with ...{vt_api_key[-4:]})",
                    file=sys.stderr,
                )
            else:
                print("[!] VirusTotal API key NOT found", file=sys.stderr)

            if abuseipdb_api_key:
                print(
                    f"[*] AbuseIPDB API key loaded (ends with ...{abuseipdb_api_key[-4:]})",
                    file=sys.stderr,
                )
            else:
                print("[!] AbuseIPDB API key NOT found", file=sys.stderr)

            if otx_api_key:
                print(
                    f"[*] AlienVault OTX API key loaded (ends with ...{otx_api_key[-4:]})",
                    file=sys.stderr,
                )
            elif _OTX_AVAILABLE:
                print("[!] AlienVault OTX API key NOT found", file=sys.stderr)
            else:
                print("[!] AlienVault OTX not available (otx_lookup.py not found)", file=sys.stderr)

        # Initialize clients with auth keys
        self.malwarebazaar = MalwareBazaar(abusech_auth_key)
        self.threatfox = ThreatFox(abusech_auth_key)
        self.urlhaus = URLhaus(abusech_auth_key)
        self.virustotal = VirusTotal(vt_api_key)
        self.abuseipdb = AbuseIPDB(abuseipdb_api_key)
        self.otx = OTXClient(otx_api_key) if _OTX_AVAILABLE else None

        self.api_status = {
            "malwarebazaar": bool(abusech_auth_key),
            "threatfox": bool(abusech_auth_key),
            "urlhaus": True,  # Works without key but better with
            "virustotal": bool(vt_api_key),
            "abuseipdb": bool(abuseipdb_api_key),
            "alienvault_otx": bool(_OTX_AVAILABLE and otx_api_key),
        }

    @staticmethod
    def _run_parallel(sources_to_query: list, ioc: str) -> list:
        """Execute all (name, func) pairs against ioc in parallel. Returns list of results."""
        source_results = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(fn, ioc): name for name, fn in sources_to_query}
            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    source_results.append(future.result())
                except Exception as e:
                    source_results.append({"source": source_name, "found": False, "error": str(e)})
        return source_results

    def triage_hash(self, hash_value: str) -> dict:
        """Triage a file hash across all sources (parallel)."""
        cache_key = f"hash:{hash_value}"
        cached = _SESSION_CACHE.get(cache_key)
        if cached:
            print(f"[*] Cache hit: {hash_value} (TTL 300s)", file=sys.stderr)
            cached["_cached"] = True
            return cached

        results = {
            "query": hash_value,
            "type": detect_ioc_type(hash_value),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": [],
            "verdict": "unknown",
            "confidence": "LOW",
            "summary": {},
        }

        sources_to_query = [
            ("malwarebazaar", self.malwarebazaar.query_hash),
            ("urlhaus", self.urlhaus.query_hash),
            ("threatfox", self.threatfox.query_ioc),
            ("virustotal", self.virustotal.query_hash),  # includes behaviour_summary internally
        ]

        results["sources"] = self._run_parallel(sources_to_query, hash_value)
        results["verdict"], results["confidence"], results["summary"] = (
            self._aggregate_hash_verdict(results["sources"])
        )

        _SESSION_CACHE.set(cache_key, results)
        return results

    def triage_ip(self, ip: str) -> dict:
        """Triage an IP address across all sources (parallel)."""
        cache_key = f"ipv4:{ip}"
        cached = _SESSION_CACHE.get(cache_key)
        if cached:
            print(f"[*] Cache hit: {ip} (TTL 300s)", file=sys.stderr)
            cached["_cached"] = True
            return cached

        results = {
            "query": ip,
            "type": "ipv4",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": [],
            "verdict": "unknown",
            "confidence": "LOW",
            "summary": {},
        }

        sources_to_query = [
            ("urlhaus", self.urlhaus.query_host),
            ("threatfox", self.threatfox.query_ioc),
            ("virustotal", self.virustotal.query_ip),
            ("abuseipdb", self.abuseipdb.query_ip),
        ]
        if self.otx:
            sources_to_query.append(("alienvault_otx", self.otx.query_ip))

        results["sources"] = self._run_parallel(sources_to_query, ip)
        results["verdict"], results["confidence"], results["summary"] = self._aggregate_ip_verdict(
            results["sources"]
        )
        results["hostnames"] = self._collect_hostnames(ip, results["sources"])

        _SESSION_CACHE.set(cache_key, results)
        return results

    def _collect_hostnames(self, ip: str, sources: list) -> list:
        """Aggregate hostnames/passive DNS for an IP from all sources + rDNS."""
        seen = {}  # hostname -> {"sources": [], "last_seen": str|None}

        def _add(hostname: str, source: str, last_seen=None):
            hostname = hostname.strip().lower().rstrip(".")
            if not hostname:
                return
            if hostname not in seen:
                seen[hostname] = {"hostname": hostname, "sources": [], "last_seen": last_seen}
            if source not in seen[hostname]["sources"]:
                seen[hostname]["sources"].append(source)
            if last_seen and not seen[hostname]["last_seen"]:
                seen[hostname]["last_seen"] = last_seen

        # rDNS via stdlib
        try:
            rdns = socket.gethostbyaddr(ip)[0]
            if rdns:
                _add(rdns, "rdns")
        except (socket.herror, socket.gaierror, OSError):
            pass

        for source in sources:
            src = source.get("source", "")

            # VirusTotal resolutions
            if src == "virustotal":
                for r in source.get("resolutions", []):
                    _add(r.get("hostname", ""), "virustotal", r.get("last_resolved"))

            # AbuseIPDB domain field
            if src == "abuseipdb" and source.get("domain"):
                _add(source["domain"], "abuseipdb")

            # AlienVault OTX passive DNS
            if src == "alienvault_otx":
                for r in source.get("passive_dns", []):
                    _add(r.get("hostname", ""), "alienvault_otx", r.get("last_seen"))

        return sorted(seen.values(), key=lambda x: x["hostname"])

    def triage_domain(self, domain: str) -> dict:
        """Triage a domain across all sources (parallel)."""
        cache_key = f"domain:{domain}"
        cached = _SESSION_CACHE.get(cache_key)
        if cached:
            print(f"[*] Cache hit: {domain} (TTL 300s)", file=sys.stderr)
            cached["_cached"] = True
            return cached

        results = {
            "query": domain,
            "type": "domain",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": [],
            "verdict": "unknown",
            "confidence": "LOW",
            "summary": {},
        }

        sources_to_query = [
            ("urlhaus", self.urlhaus.query_host),
            ("threatfox", self.threatfox.query_ioc),
            ("virustotal", self.virustotal.query_domain),
        ]
        if self.otx:
            sources_to_query.append(("alienvault_otx", self.otx.query_domain))

        results["sources"] = self._run_parallel(sources_to_query, domain)
        results["verdict"], results["confidence"], results["summary"] = (
            self._aggregate_domain_verdict(results["sources"])
        )

        # WHOIS enrichment — runs after TI sources, no API key needed
        results["whois_info"] = query_whois_domain(domain)
        # Escalate verdict if domain is newly registered and already seen as suspicious
        if results["whois_info"].get("new_domain") and results["verdict"] in (
            "suspicious",
            "clean_or_unknown",
        ):
            results["verdict"] = "suspicious"
            results["summary"]["new_domain_flag"] = True
            results["summary"]["domain_age_days"] = results["whois_info"].get("age_days")

        _SESSION_CACHE.set(cache_key, results)
        return results

    def triage_url(self, url: str) -> dict:
        """Triage a URL across all sources (parallel)."""
        cache_key = f"url:{url}"
        cached = _SESSION_CACHE.get(cache_key)
        if cached:
            print(f"[*] Cache hit: {url[:60]}... (TTL 300s)", file=sys.stderr)
            cached["_cached"] = True
            return cached

        results = {
            "query": url,
            "type": "url",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": [],
            "verdict": "unknown",
            "confidence": "LOW",
            "summary": {},
        }

        sources_to_query = [
            ("urlhaus", self.urlhaus.query_url),
            ("threatfox", self.threatfox.query_ioc),
            ("virustotal", self.virustotal.query_url),
        ]

        results["sources"] = self._run_parallel(sources_to_query, url)
        results["verdict"], results["confidence"], results["summary"] = self._aggregate_url_verdict(
            results["sources"]
        )

        _SESSION_CACHE.set(cache_key, results)
        return results

    def triage_file(self, filepath: str) -> dict:
        """Triage a file by calculating hashes and querying."""
        hashes = calculate_file_hashes(filepath)
        if "error" in hashes:
            return {"error": hashes["error"]}

        results = self.triage_hash(hashes["sha256"])
        results["file_info"] = {
            "path": filepath,
            "hashes": hashes,
        }
        return results

    def triage_auto(self, ioc: str) -> dict:
        """Auto-detect IOC type and triage."""
        ioc_type = detect_ioc_type(ioc)

        if ioc_type in ["md5", "sha1", "sha256"]:
            return self.triage_hash(ioc)
        elif ioc_type == "ipv4":
            return self.triage_ip(ioc)
        elif ioc_type == "domain":
            return self.triage_domain(ioc)
        elif ioc_type == "url":
            return self.triage_url(ioc)
        else:
            return {"error": f"Unknown IOC type: {ioc}", "query": ioc}

    def _aggregate_hash_verdict(self, sources: list) -> tuple:
        """Aggregate verdict from hash query results. Returns (verdict, confidence, summary)."""
        malware_names = set()
        tags = set()
        found_in = []
        vt_detection = None

        for source in sources:
            if source.get("found"):
                found_in.append(source["source"])

                # Extract malware family names
                if source.get("signature"):
                    malware_names.add(source["signature"])
                if source.get("popular_threat_names"):
                    malware_names.add(source["popular_threat_names"])
                if source.get("malware"):
                    malware_names.add(source["malware"])

                # Extract tags
                if source.get("tags"):
                    tags.update(source["tags"])

                # Get VT detection rate
                if source["source"] == "virustotal" and source.get("detections"):
                    vt_detection = source["detections"]

        # Determine verdict
        vt_mal = vt_detection.get("malicious", 0) if vt_detection else 0
        if not found_in:
            verdict = "clean_or_unknown"
        elif vt_mal > 5:
            verdict = "malicious"
        elif found_in:
            verdict = "suspicious"
        else:
            verdict = "unknown"

        # Confidence scoring
        if verdict == "malicious":
            if vt_mal > 15 or len(found_in) >= 3:
                confidence = "HIGH"
            elif vt_mal > 5:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
        elif verdict == "suspicious":
            confidence = "MEDIUM" if len(found_in) >= 2 else "LOW"
        else:
            confidence = "HIGH"  # Clean verdict is high confidence when nothing found it

        summary = {
            "found_in_sources": found_in,
            "malware_families": list(malware_names),
            "tags": list(tags),
        }
        if vt_detection:
            summary["virustotal_detection"] = f"{vt_mal}/{vt_detection.get('total', 0)}"

        return verdict, confidence, summary

    def _aggregate_ip_verdict(self, sources: list) -> tuple:
        """Aggregate verdict from IP query results. Returns (verdict, confidence, summary)."""
        found_in = []
        abuse_score = None
        vt_malicious = 0
        url_count = 0
        otx_pulse_count = 0

        for source in sources:
            if source.get("found"):
                found_in.append(source["source"])

                if source["source"] == "abuseipdb":
                    abuse_score = source.get("abuse_confidence_score")
                if source["source"] == "virustotal" and source.get("detections"):
                    vt_malicious = source["detections"].get("malicious", 0)
                if source["source"] == "urlhaus":
                    url_count = source.get("url_count", 0)
                if source["source"] == "alienvault_otx":
                    otx_pulse_count = source.get("pulse_count", 0)

        # Determine verdict
        if abuse_score and abuse_score > 50:
            verdict = "malicious"
        elif vt_malicious > 3:
            verdict = "malicious"
        elif otx_pulse_count > 0 or url_count > 0 or found_in:
            verdict = "suspicious"
        else:
            verdict = "clean_or_unknown"

        # Confidence scoring
        if verdict == "malicious":
            if (abuse_score and abuse_score > 75) or vt_malicious > 10 or len(found_in) >= 3:
                confidence = "HIGH"
            elif (abuse_score and abuse_score > 25) or vt_malicious > 3:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
        elif verdict == "suspicious":
            confidence = "MEDIUM" if len(found_in) >= 2 else "LOW"
        else:
            confidence = "HIGH"

        summary: dict = {"found_in_sources": found_in}
        if abuse_score is not None:
            summary["abuse_confidence_score"] = abuse_score
        if vt_malicious:
            summary["virustotal_malicious"] = vt_malicious
        if url_count:
            summary["urlhaus_url_count"] = url_count
        if otx_pulse_count:
            summary["otx_pulse_count"] = otx_pulse_count

        return verdict, confidence, summary

    def _aggregate_domain_verdict(self, sources: list) -> tuple:
        """Aggregate verdict from domain query results. Returns (verdict, confidence, summary)."""
        found_in = []
        vt_malicious = 0
        url_count = 0
        otx_pulse_count = 0

        for source in sources:
            if source.get("found"):
                found_in.append(source["source"])

                if source["source"] == "virustotal" and source.get("detections"):
                    vt_malicious = source["detections"].get("malicious", 0)
                if source["source"] == "urlhaus":
                    url_count = source.get("url_count", 0)
                if source["source"] == "alienvault_otx":
                    otx_pulse_count = source.get("pulse_count", 0)

        if vt_malicious > 3:
            verdict = "malicious"
        elif otx_pulse_count > 0 or url_count > 0 or found_in:
            verdict = "suspicious"
        else:
            verdict = "clean_or_unknown"

        # Confidence scoring
        if verdict == "malicious":
            confidence = "HIGH" if vt_malicious > 10 or len(found_in) >= 3 else "MEDIUM"
        elif verdict == "suspicious":
            confidence = "MEDIUM" if len(found_in) >= 2 else "LOW"
        else:
            confidence = "HIGH"

        summary = {
            "found_in_sources": found_in,
            "virustotal_malicious": vt_malicious,
            "urlhaus_url_count": url_count,
        }
        if otx_pulse_count:
            summary["otx_pulse_count"] = otx_pulse_count

        return verdict, confidence, summary

    def _aggregate_url_verdict(self, sources: list) -> tuple:
        """Aggregate verdict from URL query results. Returns (verdict, confidence, summary)."""
        found_in = []
        threat_type = None
        vt_malicious = 0
        vt_detection_rate = None

        for source in sources:
            if source.get("found"):
                found_in.append(source["source"])
                if source.get("threat"):
                    threat_type = source["threat"]
                if source["source"] == "virustotal" and source.get("detections"):
                    vt_malicious = source["detections"].get("malicious", 0)
                    vt_detection_rate = source.get("detection_rate")

        if vt_malicious > 3 or (found_in and "urlhaus" in found_in):
            verdict = "malicious"
        elif found_in or vt_malicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean_or_unknown"

        # Confidence scoring
        if verdict == "malicious":
            confidence = "HIGH" if vt_malicious > 10 or len(found_in) >= 2 else "MEDIUM"
        elif verdict == "suspicious":
            confidence = "LOW"
        else:
            confidence = "HIGH"

        summary: dict = {"found_in_sources": found_in, "threat_type": threat_type}
        if vt_detection_rate:
            summary["virustotal_detection"] = vt_detection_rate

        return verdict, confidence, summary


def format_triage_report(results: dict, format_type: str = "text", use_color: bool = False) -> str:
    """Format triage results for output."""

    if format_type == "json":
        return json.dumps(results, indent=2, default=str)

    if not use_color:
        Colors.disable()

    SEP = "=" * 70
    lines = []
    lines.append(Colors.bold(SEP))
    lines.append(Colors.bold("  MALWARE TRIAGE REPORT"))
    lines.append(Colors.bold(SEP))

    lines.append(f"\n{Colors.section('[QUERY]')}")
    lines.append(f"  IOC:       {Colors.bold(results.get('query', 'N/A'))}")
    lines.append(f"  Type:      {results.get('type', 'N/A')}")
    lines.append(f"  Timestamp: {results.get('timestamp', 'N/A')}")

    # File info
    if results.get("file_info"):
        fi = results["file_info"]
        lines.append(f"\n{Colors.section('[FILE INFO]')}")
        lines.append(f"  Path:   {fi['path']}")
        lines.append(f"  MD5:    {fi['hashes'].get('md5')}")
        lines.append(f"  SHA1:   {fi['hashes'].get('sha1')}")
        lines.append(f"  SHA256: {Colors.bold(fi['hashes'].get('sha256', ''))}")
        lines.append(f"  Size:   {fi['hashes'].get('size', 0):,} bytes")

    # Verdict + Confidence
    verdict = results.get("verdict", "unknown")
    confidence = results.get("confidence", "")
    verdict_emoji = {
        "malicious": "🔴",
        "suspicious": "🟡",
        "clean_or_unknown": "🟢",
        "unknown": "⚪",
    }.get(verdict, "⚪")
    conf_suffix = f"  (confidence: {confidence})" if confidence else ""
    lines.append(
        f"\n{Colors.section('[VERDICT]')} {verdict_emoji} {Colors.verdict(verdict)}{conf_suffix}"
    )
    if results.get("_cached"):
        lines.append(f"  {Colors.dim('(result served from session cache)')}")

    # Summary
    summary = results.get("summary", {})
    if summary:
        lines.append(f"\n{Colors.section('[SUMMARY]')}")
        if summary.get("found_in_sources"):
            lines.append(f"  Found in:  {Colors.bold(', '.join(summary['found_in_sources']))}")
        if summary.get("malware_families"):
            lines.append(f"  Malware:   {Colors.warn(', '.join(summary['malware_families']))}")
        if summary.get("virustotal_detection"):
            lines.append(f"  VT Score:  {Colors.bold(summary['virustotal_detection'])}")
        if summary.get("abuse_confidence_score") is not None:
            score = summary["abuse_confidence_score"]
            score_str = f"{score}%"
            lines.append(
                f"  AbuseIPDB: {Colors.danger(score_str) if score > 50 else Colors.warn(score_str) if score > 20 else score_str}"
            )
        if summary.get("otx_pulse_count"):
            lines.append(f"  OTX Pulses: {Colors.bold(str(summary['otx_pulse_count']))}")
        if summary.get("new_domain_flag"):
            age = summary.get("domain_age_days", "?")
            lines.append(f"  {Colors.danger(f'⚠  NEW DOMAIN — registered {age} days ago')}")
        if results.get("hostnames"):
            lines.append(f"  Hostnames: {len(results['hostnames'])} unique")
        if summary.get("tags"):
            lines.append(f"  Tags:      {', '.join(summary['tags'][:10])}")

    # VT Behaviour Summary (hash lookups only)
    beh = None
    for src in results.get("sources", []):
        if src.get("source") == "virustotal" and src.get("behaviour_summary"):
            beh = src["behaviour_summary"]
            break
    if beh:
        has_any = any(
            [
                beh.get("dns_lookups"),
                beh.get("ip_traffic"),
                beh.get("http_conversations"),
                beh.get("files_written"),
                beh.get("processes_created"),
                beh.get("registry_keys_set"),
            ]
        )
        if has_any:
            lines.append(f"\n{Colors.section('[VT BEHAVIOUR]')}")

            dns = beh.get("dns_lookups", [])
            if dns:
                lines.append(f"  DNS Lookups ({len(dns)}):")
                for entry in dns:
                    if isinstance(entry, dict):
                        host = entry.get("hostname", entry.get("host", str(entry)))
                        ips = ", ".join(entry.get("resolved_ips", [])[:4])
                        lines.append(f"    {Colors.bold(host)}" + (f"  → {ips}" if ips else ""))
                    else:
                        lines.append(f"    {entry}")

            ip_traffic = beh.get("ip_traffic", [])
            if ip_traffic:
                lines.append(f"  Network Connections ({len(ip_traffic)}):")
                for conn in ip_traffic:
                    if isinstance(conn, dict):
                        dst = conn.get("destination_ip", "?")
                        port = conn.get("destination_port", "?")
                        proto = conn.get("transport_layer_protocol", "")
                        lines.append(f"    {Colors.warn(dst)}:{port}  {proto}")
                    else:
                        lines.append(f"    {conn}")

            http = beh.get("http_conversations", [])
            if http:
                lines.append(f"  HTTP Requests ({len(http)}):")
                for req in http:
                    if isinstance(req, dict):
                        method = req.get("request_method", "GET")
                        url_val = req.get("url", req.get("request_url", "?"))
                        status = req.get("response_status_code", "")
                        status_str = f"  → {status}" if status else ""
                        lines.append(f"    {method} {url_val[:80]}{status_str}")
                    else:
                        lines.append(f"    {req}")

            files_w = beh.get("files_written", [])
            if files_w:
                lines.append(f"  Files Written/Dropped ({len(files_w)}):")
                for f in files_w[:8]:
                    path = f if isinstance(f, str) else f.get("path", str(f))
                    lines.append(f"    {path}")

            procs = beh.get("processes_created", [])
            if procs:
                lines.append(f"  Processes Created ({len(procs)}):")
                for p in procs[:5]:
                    if isinstance(p, dict):
                        name = p.get("process_name", p.get("name", ""))
                        cmd = p.get("command_line", "")
                        display = cmd[:100] if cmd else name
                        lines.append(f"    {Colors.warn(display)}")
                    else:
                        lines.append(f"    {str(p)[:100]}")

            reg = beh.get("registry_keys_set", [])
            if reg:
                lines.append(f"  Registry Keys Set ({len(reg)}):")
                for r in reg[:5]:
                    if isinstance(r, dict):
                        key = r.get("key", str(r))
                        lines.append(f"    {key[:100]}")
                    else:
                        lines.append(f"    {str(r)[:100]}")

    # WHOIS (domain lookups only)
    whois = results.get("whois_info", {})
    if whois and whois.get("found"):
        lines.append(f"\n{Colors.section('[WHOIS]')}")
        lines.append(f"  Registrar:   {whois.get('registrar', 'N/A')}")
        created = whois.get("creation_date", "N/A")
        age = whois.get("age_days")
        age_str = f"  ({age} days old)" if age is not None else ""
        if whois.get("new_domain"):
            lines.append(
                f"  Registered:  {Colors.danger(str(created) + age_str + '  ⚠ NEWLY REGISTERED')}"
            )
        else:
            lines.append(f"  Registered:  {created}{age_str}")
        lines.append(f"  Expires:     {whois.get('expiration_date', 'N/A')}")
        if whois.get("nameservers"):
            lines.append(f"  Nameservers: {', '.join(whois['nameservers'])}")
    elif whois and whois.get("error") and "not installed" in whois.get("error", ""):
        lines.append(f"\n{Colors.section('[WHOIS]')} {Colors.dim(whois['error'])}")

    # Hostnames / Passive DNS (IP lookups only)
    hostnames = results.get("hostnames", [])
    if hostnames:
        lines.append(f"\n{Colors.section('[HOSTNAMES / PASSIVE DNS]')}  ({len(hostnames)} unique)")
        for entry in hostnames:
            src_tag = ", ".join(entry["sources"])
            last = f"  (last: {entry['last_seen']})" if entry.get("last_seen") else ""
            lines.append(f"  {entry['hostname']:<45} [{Colors.dim(src_tag)}]{last}")

    # Source details
    lines.append(f"\n{Colors.section('[SOURCE DETAILS]')}")
    for source in results.get("sources", []):
        source_name = source.get("source", "unknown").upper()
        found = source.get("found", False)
        found_str = Colors.ok("✓") if found else Colors.dim("✗")
        lines.append(f"\n  [{Colors.bold(source_name)}] {found_str}")

        if source.get("error"):
            lines.append(f"    {Colors.dim('Error: ' + source['error'])}")
            continue

        if not found:
            lines.append(f"    {Colors.dim('Not found in database')}")
            continue

        if source.get("signature"):
            lines.append(f"    Malware:    {Colors.warn(source['signature'])}")
        if source.get("popular_threat_names"):
            lines.append(f"    Threat:     {Colors.warn(source['popular_threat_names'])}")
        if source.get("detection_rate"):
            lines.append(f"    Detection:  {Colors.bold(source['detection_rate'])}")
        if source.get("title"):
            lines.append(f"    Page title: {source['title']}")
        if source.get("final_url") and source.get("final_url") != source.get("url"):
            lines.append(f"    Final URL:  {source['final_url']}")
        if source.get("threat_names"):
            lines.append(f"    Threats:    {Colors.warn(', '.join(source['threat_names'][:5]))}")
        if source.get("first_seen"):
            lines.append(f"    First seen: {source['first_seen']}")
        if source.get("abuse_confidence_score") is not None:
            score = source["abuse_confidence_score"]
            score_str = f"{score}%"
            lines.append(
                f"    Abuse score: {Colors.danger(score_str) if score > 50 else score_str}"
            )
        if source.get("total_reports"):
            lines.append(f"    Reports:    {source['total_reports']}")
        if source.get("url_count"):
            lines.append(f"    Malicious URLs: {source['url_count']}")
        if source.get("pulse_count"):
            lines.append(f"    OTX Pulses: {Colors.bold(str(source['pulse_count']))}")
        if source.get("pulse_names"):
            for name in source["pulse_names"][:3]:
                lines.append(f"      - {name}")
        if source.get("malware_sample_count"):
            lines.append(f"    Malware samples: {source['malware_sample_count']}")
        if source.get("tags"):
            lines.append(f"    Tags: {', '.join(source['tags'][:5])}")
        if source.get("reputation") is not None:
            rep = source["reputation"]
            rep_str = f"{rep:+d}"
            lines.append(
                f"    Reputation: {Colors.danger(rep_str) if rep < 0 else Colors.ok(rep_str) if rep > 0 else rep_str}"
            )
        if source.get("signature_info"):
            sig = source["signature_info"]
            if isinstance(sig, dict):
                product = sig.get("product") or sig.get("name") or ""
                publisher = sig.get("publisher") or sig.get("signers") or ""
                verified = sig.get("verified") or ""
                if product or publisher:
                    lines.append(f"    Signed by:  {product} / {publisher}".rstrip(" /"))
                if verified:
                    lines.append(f"    Verified:   {verified}")
            else:
                lines.append(f"    Sig info:   {sig}")
        if source.get("tags") and "revoked-cert" in source["tags"]:
            lines.append(
                f"    {Colors.danger('⚠ REVOKED CERTIFICATE — signing certificate has been revoked')}"
            )
        if source.get("sandbox_verdicts"):
            vt_mal_count = source.get("detections", {}).get("malicious", 0)
            lines.append(f"    Sandboxes:")
            for sbox, sv in source["sandbox_verdicts"].items():
                cat = sv.get("category", "?")
                conf_val = sv.get("confidence", "")
                names = (
                    ", ".join(sv.get("malware_names") or sv.get("malware_classification", []))
                    or "—"
                )
                conf_disp = f" conf:{conf_val}" if conf_val != "" else ""
                evasion_flag = ""
                if cat == "harmless" and vt_mal_count > 5:
                    evasion_flag = f"  {Colors.warn('⚠ POSSIBLE SANDBOX EVASION')}"
                cat_colored = (
                    Colors.warn(cat) if cat not in ("harmless", "clean") else Colors.ok(cat)
                )
                lines.append(
                    f"      {Colors.dim(sbox)}: {cat_colored}{conf_disp} ({names}){evasion_flag}"
                )
        if source.get("last_analysis_results"):
            flagged = [
                (vendor, data.get("result", "?"))
                for vendor, data in source["last_analysis_results"].items()
                if data.get("category") in ("malicious", "suspicious")
            ]
            if flagged:
                lines.append(f"    Detections ({len(flagged)} vendors):")
                for vendor, vresult in flagged[:10]:
                    lines.append(f"      {vendor:<20} {Colors.warn(vresult)}")

    lines.append("\n" + Colors.bold(SEP))

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Malware triage - Multi-source threat intelligence lookup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 44d88612fea8a8f36de82e1278abb02f                    # MD5 hash
  %(prog)s -t hash e3b0c44298fc1c149afbf4c8996fb924...         # SHA256 hash
  %(prog)s -t ip 45.33.32.156                                  # IP address
  %(prog)s -t domain evil.com                                  # Domain
  %(prog)s -t url http://evil.com/malware.exe                  # URL
  %(prog)s -t file /path/to/sample.exe                         # File
  %(prog)s --batch iocs.txt                                    # Batch mode

API Key Configuration (in priority order):
  1. Command line: --abusech-key, --vt-key, --abuseipdb-key
  2. Environment variables: ABUSECH_AUTH_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
  3. Config file: ~/.config/malware-triage/config.json

Create config file:
  %(prog)s --init-config

Get your API keys from:
  - abuse.ch (MalwareBazaar/ThreatFox): https://auth.abuse.ch/
  - VirusTotal: https://www.virustotal.com/gui/my-apikey
  - AbuseIPDB: https://www.abuseipdb.com/account/api
        """,
    )
    parser.add_argument("ioc", nargs="?", help="IOC to triage (hash, IP, domain, URL)")
    parser.add_argument(
        "-t",
        "--type",
        choices=["hash", "ip", "domain", "url", "file", "auto"],
        default="auto",
        help="IOC type (default: auto-detect)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--batch", help="File containing IOCs (one per line)")
    parser.add_argument("--status", action="store_true", help="Show API configuration status")
    parser.add_argument("--init-config", action="store_true", help="Create default config file")
    parser.add_argument("--abusech-key", help="abuse.ch Auth-Key (for MalwareBazaar/ThreatFox)")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--abuseipdb-key", help="AbuseIPDB API key")
    parser.add_argument("--otx-key", help="AlienVault OTX API key")

    args = parser.parse_args()

    if args.init_config:
        create_default_config()
        return

    triage = MalwareTriage(
        vt_key=args.vt_key,
        abuseipdb_key=args.abuseipdb_key,
        abusech_key=args.abusech_key,
        otx_key=args.otx_key,
    )

    if args.status:
        print("API Configuration Status:")
        print("-" * 40)
        for api, configured in triage.api_status.items():
            status = "✓ Configured" if configured else "✗ Not configured"
            print(f"  {api:<15} {status}")

        # Show config file location
        print()
        print("Config file locations (in priority order):")
        config_paths = [
            Path.home() / ".config" / "malware-triage" / "config.json",
            Path.home() / ".malware-triage.json",
            Path("config.json"),
        ]
        for p in config_paths:
            exists = "✓" if p.exists() else "✗"
            print(f"  {exists} {p}")

        print()
        print("Run with --init-config to create a config file.")
        return

    if not args.ioc and not args.batch:
        parser.print_help()
        return

    # Process IOCs
    results_list = []

    if args.batch:
        iocs = Path(args.batch).read_text().strip().split("\n")
        for ioc in iocs:
            ioc = ioc.strip()
            if not ioc or ioc.startswith("#"):
                continue
            print(f"Triaging: {ioc}...", file=sys.stderr)
            result = triage.triage_auto(ioc)
            results_list.append(result)
    else:
        if args.type == "file":
            result = triage.triage_file(args.ioc)
        elif args.type == "hash":
            result = triage.triage_hash(args.ioc)
        elif args.type == "ip":
            result = triage.triage_ip(args.ioc)
        elif args.type == "domain":
            result = triage.triage_domain(args.ioc)
        elif args.type == "url":
            result = triage.triage_url(args.ioc)
        else:
            result = triage.triage_auto(args.ioc)
        results_list.append(result)

    # Format output
    if args.batch and args.format == "json":
        output = json.dumps(results_list, indent=2, default=str)
    elif args.batch:
        use_color = sys.stdout.isatty() and args.format != "json" and not args.output
        output = "\n\n".join(
            format_triage_report(r, args.format, use_color=use_color) for r in results_list
        )
    else:
        use_color = sys.stdout.isatty() and args.format != "json" and not args.output
        output = format_triage_report(results_list[0], args.format, use_color=use_color)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
