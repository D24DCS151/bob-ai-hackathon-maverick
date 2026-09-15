"""
THREATICAP Demo Ingestion Script
=================================
Seeds the live API with a realistic multi-source threat scenario
for demonstration purposes.

Scenario: APT-style lateral movement campaign targeting a national SOC
  - Wave 1: Phishing / initial access (SIEM)
  - Wave 2: Credential theft + lateral movement (EDR)
  - Wave 3: C2 beacon + data staging (NETWORK_SENSOR)
  - Wave 4: Exfiltration attempt (STIX intel feed)

Run AFTER starting the API:
    $env:THREATICAP_AUTH_DISABLED="true"
    uvicorn threaticap.api.app:app --host 0.0.0.0 --port 8080 --reload

Then run this script:
    python scripts/demo_ingest.py
"""
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

BASE_URL = "http://localhost:8080"
HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}

SHARED_IP = "185.220.101.47"   # Simulated C2 IP (shared across all waves)
SHARED_HASH = "a" * 64          # Simulated malware SHA-256


def post(path: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  ERROR {e.code}: {e.read().decode()[:200]}")
        return {}


def get(path: str) -> dict:
    req = urllib.request.Request(f"{BASE_URL}{path}", headers=HEADERS)
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_text": raw.decode()}


def wait_for_api(retries: int = 15) -> bool:
    print("Waiting for API to be ready...", end="", flush=True)
    for _ in range(retries):
        try:
            get("/api/v1/health")
            print(" OK")
            return True
        except Exception:
            print(".", end="", flush=True)
            time.sleep(1)
    print(" TIMEOUT")
    return False


def make_alert(
    source_ref, source_type, source_id,
    severity, title, description,
    observables, mitre_ids,
    asset_id=None, hostname=None, criticality=0.5,
    network_segment="CORP-INTERNAL",
    offset_minutes=0,
    source_reliability=0.85,
    tlp="TLP:AMBER",
    threat_actor=None,
    campaign=None,
):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).isoformat()
    return {
        "source_ref": source_ref,
        "source_type": source_type,
        "source_id": source_id,
        "source_reliability": source_reliability,
        "event_time": ts,
        "severity": severity,
        "confidence": 0.85,
        "title": title,
        "description": description,
        "observables": observables,
        "mitre_technique_ids": mitre_ids,
        "asset_context": {
            "asset_id": asset_id or "",
            "hostname": hostname or "",
            "ip_addresses": [],
            "criticality": criticality,
            "network_segment": network_segment,
            "tags": [],
        },
        "tlp": tlp,
        "threat_actor": threat_actor,
        "campaign": campaign,
    }


def run_demo():
    if not wait_for_api():
        print("API not reachable. Start it first:")
        print("  $env:THREATICAP_AUTH_DISABLED='true'")
        print("  uvicorn threaticap.api.app:app --host 0.0.0.0 --port 8080 --reload")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("  THREATICAP DEMO — APT Campaign Scenario")
    print("=" * 60)

    # ------------------------------------------------------------------
    # WAVE 1 — Phishing / Initial Access (SIEM)
    # ------------------------------------------------------------------
    print("\n[1/4] Submitting Wave 1: Phishing / Initial Access (SIEM)...")
    wave1 = [
        make_alert(
            source_ref="SIEM-EVT-001",
            source_type="SIEM",
            source_id="siem-prod",
            severity="HIGH",
            title="Suspicious macro execution in Word document — possible spear-phish",
            description="User workstation-alpha executed a VBA macro that spawned cmd.exe and made an outbound HTTP connection.",
            observables=[
                {"type": "ipv4-addr",   "value": SHARED_IP,   "confidence": 0.9, "context": "C2 callback"},
                {"type": "file:hashes", "value": SHARED_HASH, "confidence": 0.95, "context": "Malicious Word doc"},
                {"type": "domain-name", "value": "update-cdn-service.com", "confidence": 0.88, "context": "C2 domain"},
            ],
            mitre_ids=["T1566", "T1059"],
            asset_id="ASSET-003",
            hostname="workstation-alpha.corp.internal",
            criticality=0.60,
            network_segment="OPS-WORKSTATIONS",
            offset_minutes=90,
            threat_actor="APT29",
            campaign="OPERATION-COZY-BEAR",
        ),
        make_alert(
            source_ref="SIEM-EVT-002",
            source_type="SIEM",
            source_id="siem-prod",
            severity="MEDIUM",
            title="Outbound connection to known malicious IP",
            description="Repeated beaconing to 185.220.101.47 on port 443 — suspicious JA3 fingerprint.",
            observables=[
                {"type": "ipv4-addr", "value": SHARED_IP, "confidence": 0.92, "context": "Malicious IP"},
                {"type": "network-traffic", "value": "185.220.101.47:443", "confidence": 0.80, "context": "C2 beacon"},
            ],
            mitre_ids=["T1071"],
            asset_id="ASSET-003",
            hostname="workstation-alpha.corp.internal",
            criticality=0.60,
            network_segment="OPS-WORKSTATIONS",
            offset_minutes=85,
            threat_actor="APT29",
            campaign="OPERATION-COZY-BEAR",
        ),
    ]
    r = post("/api/v1/ingest/alerts", {"alerts": wave1, "run_pipeline": False})
    print(f"  Submitted {len(wave1)} alerts → {r.get('accepted', 0)} accepted")

    # ------------------------------------------------------------------
    # WAVE 2 — Credential Theft + Lateral Movement (EDR)
    # ------------------------------------------------------------------
    print("\n[2/4] Submitting Wave 2: Credential Theft + Lateral Movement (EDR)...")
    wave2 = [
        make_alert(
            source_ref="EDR-EVT-001",
            source_type="EDR",
            source_id="edr-crowdstrike",
            severity="CRITICAL",
            title="LSASS credential dumping detected — Mimikatz pattern",
            description="Process lsass.exe accessed by rundll32.exe with known Mimikatz memory access pattern.",
            observables=[
                {"type": "process",     "value": "rundll32.exe -> lsass.exe", "confidence": 0.97, "context": "Credential dump"},
                {"type": "file:hashes", "value": SHARED_HASH, "confidence": 0.95, "context": "Mimikatz loader"},
                {"type": "ipv4-addr",   "value": SHARED_IP,   "confidence": 0.9,  "context": "C2 exfil channel"},
            ],
            mitre_ids=["T1003", "T1548"],
            asset_id="ASSET-003",
            hostname="workstation-alpha.corp.internal",
            criticality=0.60,
            network_segment="OPS-WORKSTATIONS",
            offset_minutes=75,
            source_reliability=0.95,
            threat_actor="APT29",
            campaign="OPERATION-COZY-BEAR",
        ),
        make_alert(
            source_ref="EDR-EVT-002",
            source_type="EDR",
            source_id="edr-crowdstrike",
            severity="CRITICAL",
            title="Pass-the-Hash lateral movement to Domain Controller",
            description="Stolen NTLM hash used to authenticate to dc01.corp.internal from workstation-alpha.",
            observables=[
                {"type": "ipv4-addr",   "value": "10.0.1.50",  "confidence": 0.95, "context": "Target: DC01"},
                {"type": "file:hashes", "value": SHARED_HASH,  "confidence": 0.95, "context": "Attacker tool"},
            ],
            mitre_ids=["T1021", "T1078"],
            asset_id="ASSET-001",
            hostname="dc01.corp.internal",
            criticality=0.95,
            network_segment="CORP-MGMT",
            offset_minutes=65,
            source_reliability=0.95,
            threat_actor="APT29",
            campaign="OPERATION-COZY-BEAR",
            tlp="TLP:RED",
        ),
    ]
    r = post("/api/v1/ingest/alerts", {"alerts": wave2, "run_pipeline": False})
    print(f"  Submitted {len(wave2)} alerts → {r.get('accepted', 0)} accepted")

    # ------------------------------------------------------------------
    # WAVE 3 — C2 Beacon + Data Staging (NETWORK SENSOR)
    # ------------------------------------------------------------------
    print("\n[3/4] Submitting Wave 3: C2 Beaconing + Data Staging (Network Sensor)...")
    wave3 = [
        make_alert(
            source_ref="NET-EVT-001",
            source_type="NETWORK_SENSOR",
            source_id="network-ids-01",
            severity="HIGH",
            title="Encrypted C2 channel active — periodic beaconing detected",
            description="Beaconing pattern to 185.220.101.47 every 300 seconds — consistent with Cobalt Strike or Brute Ratel C4.",
            observables=[
                {"type": "ipv4-addr",   "value": SHARED_IP, "confidence": 0.93, "context": "Active C2"},
                {"type": "domain-name", "value": "update-cdn-service.com", "confidence": 0.88, "context": "C2 domain"},
                {"type": "network-traffic", "value": "beacon-interval-300s", "confidence": 0.85, "context": "C2 beacon pattern"},
            ],
            mitre_ids=["T1071", "T1095"],
            asset_id="ASSET-001",
            hostname="dc01.corp.internal",
            criticality=0.95,
            network_segment="CORP-MGMT",
            offset_minutes=50,
            threat_actor="APT29",
            campaign="OPERATION-COZY-BEAR",
            tlp="TLP:RED",
        ),
        make_alert(
            source_ref="NET-EVT-002",
            source_type="NETWORK_SENSOR",
            source_id="network-ids-01",
            severity="HIGH",
            title="Large internal data staging — possible pre-exfil collection",
            description="Unusual volume of SMB reads from fileserver01 to workstation-alpha — 4.2GB in 15 minutes.",
            observables=[
                {"type": "ipv4-addr", "value": "10.0.1.51", "confidence": 0.88, "context": "Source: fileserver01"},
                {"type": "ipv4-addr", "value": "10.0.1.50", "confidence": 0.88, "context": "Staging: dc01"},
            ],
            mitre_ids=["T1039", "T1005"],
            asset_id="ASSET-002",
            hostname="fileserver01.corp.internal",
            criticality=0.85,
            network_segment="CORP-DATA",
            offset_minutes=40,
            threat_actor="APT29",
            campaign="OPERATION-COZY-BEAR",
            tlp="TLP:RED",
        ),
    ]
    r = post("/api/v1/ingest/alerts", {"alerts": wave3, "run_pipeline": False})
    print(f"  Submitted {len(wave3)} alerts → {r.get('accepted', 0)} accepted")

    # ------------------------------------------------------------------
    # WAVE 4 — Exfiltration attempt (STIX intel feed)
    # ------------------------------------------------------------------
    print("\n[4/4] Submitting Wave 4: Exfiltration Attempt (STIX Intel)...")
    wave4 = [
        make_alert(
            source_ref="STIX-IND-001",
            source_type="STIX_TAXII",
            source_id="national-tip",
            severity="CRITICAL",
            title="DNS tunnelling exfiltration — classified data exfil pattern",
            description="DNS queries to update-cdn-service.com encoding base64 data — classic DNS exfiltration technique.",
            observables=[
                {"type": "domain-name", "value": "update-cdn-service.com", "confidence": 0.97, "context": "DNS exfil domain"},
                {"type": "ipv4-addr",   "value": SHARED_IP,                "confidence": 0.97, "context": "Exfil endpoint"},
                {"type": "file:hashes", "value": SHARED_HASH,              "confidence": 0.97, "context": "Exfil tool"},
            ],
            mitre_ids=["T1041", "T1048"],
            asset_id="ASSET-001",
            hostname="dc01.corp.internal",
            criticality=0.95,
            network_segment="CORP-MGMT",
            offset_minutes=25,
            source_reliability=0.90,
            threat_actor="APT29",
            campaign="OPERATION-COZY-BEAR",
            tlp="TLP:RED",
        ),
    ]
    r = post("/api/v1/ingest/alerts", {"alerts": wave4, "run_pipeline": False})
    print(f"  Submitted {len(wave4)} alerts → {r.get('accepted', 0)} accepted")

    # ------------------------------------------------------------------
    # Run the pipeline
    # ------------------------------------------------------------------
    print("\n[*] Running correlation pipeline across all ingested alerts...")
    time.sleep(0.5)
    r = post("/api/v1/pipeline/run", {})
    print(f"  Threats created  : {r.get('threats_created', 0)}")
    print(f"  CRITICAL         : {r.get('threats_critical', 0)}")
    print(f"  HIGH             : {r.get('threats_high', 0)}")
    print(f"  MEDIUM           : {r.get('threats_medium', 0)}")
    print(f"  LOW              : {r.get('threats_low', 0)}")
    print(f"  Reports generated: {r.get('reports_generated', 0)}")

    # ------------------------------------------------------------------
    # Show results
    # ------------------------------------------------------------------
    print("\n[*] Fetching prioritised threat list...")
    threats = get("/api/v1/threats")
    items = threats.get("threats", [])
    print(f"  Total threats in queue: {len(items)}")
    for t in items[:5]:
        score_val = t.get("score", 0.0) if isinstance(t.get("score"), (int, float)) else t.get("score", {}).get("final_score", 0.0)
        tier_val = t.get("priority") if isinstance(t.get("priority"), str) else t.get("score", {}).get("priority_tier", "?")
        alert_cnt = t.get("alert_count", 0) if "alert_count" in t else t.get("threat", {}).get("alert_count", 0)
        conf_val = t.get("correlation_confidence", 0.0) if "correlation_confidence" in t else t.get("threat", {}).get("correlation_confidence", 0.0)
        title_val = t.get("title", "") if "title" in t else t.get("threat", {}).get("title", "")
        mitre_val = t.get("mitre_technique_ids", []) if "mitre_technique_ids" in t else t.get("threat", {}).get("mitre_technique_ids", [])
        print(f"\n  {'─'*50}")
        print(f"  [{tier_val}] score={score_val:.1f}  "
              f"alerts={alert_cnt}  "
              f"confidence={conf_val:.2f}")
        print(f"  Title : {title_val[:70]}")
        print(f"  MITRE : {', '.join(mitre_val[:5])}")

    # Show top BLUF (plain text)
    if items:
        top_threat_id = items[0].get("threat_id") or items[0].get("threat", {}).get("threat_id")
        print(f"\n[*] Fetching BLUF report for top threat ({top_threat_id[:8]}...)...")
        bluf = get(f"/api/v1/threats/{top_threat_id}/bluf?format=text")
        text_out = bluf.get("_text", "") or bluf.get("bottom_line", "")
        if text_out:
            print(text_out[:2000])
        else:
            # fallback: show JSON bottom_line
            print(bluf.get("bottom_line", "(BLUF not available)"))

    print("\n" + "=" * 60)
    print("  DEMO COMPLETE — Access the live API at:")
    print("  http://localhost:8080/docs   (Swagger UI)")
    print("  http://localhost:8080/api/v1/threats")
    print("  http://localhost:8080/api/v1/reports")
    print("  http://localhost:8080/api/v1/health")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run_demo()
