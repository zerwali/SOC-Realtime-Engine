
import getpass
import json
import time
import uuid
import logging
import requests
import urllib3

from pathlib import Path
from datetime import datetime, timezone
from emailsender import send_email_notification

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
INDEXER_URL = "https://127.0.0.1:9200/wazuh-alerts-*/_search"

POLL_INTERVAL = 5
CORRELATION_WINDOW = 300  # 5 minutes
TARGET_RULES = ["100100", "100101"]

INCIDENT_FILE = Path("incidents.json")
STATE_FILE = Path("processed_alerts.json")
LOG_FILE = Path("engine.log")

# Logging goes to a file, not the terminal.
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def load_json(path, default):
    if not path.exists():
        return default

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path, data):
    path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8"
    )


def calculate_risk(incident):
    score = 0
    reasons = []

    rule_ids = set(incident["rule_ids"])

    if "100101" in rule_ids:
        score += 40
        reasons.append("Scanner user-agent detected (+40)")

    if "100100" in rule_ids:
        score += 40
        reasons.append("Web enumeration threshold triggered (+40)")

    if incident["distinct_urls"] >= 20:
        score += 20
        reasons.append("20 or more distinct URLs (+20)")

    if incident["alert_count"] >= 30:
        score += 10
        reasons.append("30 or more alerts (+10)")

    incident["risk_score"] = min(score, 100)
    incident["risk_reasons"] = reasons


def parse_timestamp(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def create_incident(alert):
    data = alert.get("data", {})
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    timestamp = alert.get("@timestamp")

    return {
        "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
        "source_ip": data.get("srcip"),
        "target_agent": agent.get("name"),
        "first_seen": timestamp,
        "last_seen": timestamp,
        "alert_count": 0,
        "distinct_urls": 0,
        "urls": [],
        "rule_ids": [],
        "detections": [],
        "http_statuses": [],
        "risk_score": 0,
        "risk_reasons": [],
        "email_sent": False,
        "alerts": []
    }


def add_alert_to_incident(alert, incident):
    data = alert.get("data", {})
    rule = alert.get("rule", {})

    timestamp = alert.get("@timestamp")
    url = data.get("url")
    rule_id = str(rule.get("id", "unknown"))
    description = rule.get("description", "Unknown detection")
    status = data.get("id")

    incident["last_seen"] = timestamp
    incident["alert_count"] += 1

    if url and url not in incident["urls"]:
        incident["urls"].append(url)

    incident["distinct_urls"] = len(incident["urls"])

    if rule_id not in incident["rule_ids"]:
        incident["rule_ids"].append(rule_id)

    if description not in incident["detections"]:
        incident["detections"].append(description)

    if status is not None and str(status) not in incident["http_statuses"]:
        incident["http_statuses"].append(str(status))

    incident["alerts"].append({
        "timestamp": timestamp,
        "url": url,
        "http_status": status,
        "rule_id": rule_id,
        "description": description,
        "full_log": alert.get("full_log")
    })

    calculate_risk(incident)


def process_alert(alert, incidents):
    data = alert.get("data", {})
    agent = alert.get("agent", {})

    source_ip = data.get("srcip")
    target_agent = agent.get("name")

    if not source_ip or not target_agent:
        return

    timestamp = alert.get("@timestamp")

    if not timestamp:
        return

    alert_time = parse_timestamp(timestamp)

    matching_incident = None

    for incident in reversed(incidents):
        same_source = incident["source_ip"] == source_ip
        same_target = incident["target_agent"] == target_agent

        if not same_source or not same_target:
            continue

        last_seen = parse_timestamp(incident["last_seen"])
        difference = (alert_time - last_seen).total_seconds()

        if 0 <= difference <= CORRELATION_WINDOW:
            matching_incident = incident
            break

    if matching_incident is None:
        matching_incident = create_incident(alert)
        incidents.append(matching_incident)

    add_alert_to_incident(alert, matching_incident)


def fetch_new_alerts(session, processed_ids):
    body = {
        "size": 500,
        "query": {
            "bool": {
                "filter": [
                    {"terms": {"rule.id": TARGET_RULES}},
                    {"range": {"@timestamp": {"gte": "now-2m"}}}
                ]
            }
        },
        "sort": [
            {"@timestamp": {"order": "asc"}}
        ]
    }

    response = session.post(
        INDEXER_URL,
        json=body,
        timeout=20
    )

    response.raise_for_status()

    hits = response.json().get("hits", {}).get("hits", [])

    new_alerts = []

    for hit in hits:
        alert_id = hit.get("_id")

        if alert_id and alert_id not in processed_ids:
            new_alerts.append(hit)

    return new_alerts

# email builder
def build_incident_email(incident):
    subject = (
        f"[SOC ALERT] Risk {incident['risk_score']}/100 "
        f"- Web Security Incident"
    )

    urls = incident.get("urls", [])
    sample_urls = urls[:10]

    url_text = (
        "\n".join(f"  - {url}" for url in sample_urls)
        if sample_urls
        else "  No URL evidence available."
    )

    reasons = incident.get("risk_reasons", [])
    reason_text = (
        "\n".join(f"  - {reason}" for reason in reasons)
        if reasons
        else "  No scoring reasons recorded."
    )

    body = f"""
        SECURITY INCIDENT REPORT
        ========================

        Incident ID: {incident.get('incident_id', 'Unknown')}
        Risk score: {incident.get('risk_score', 0)}/100

        SOURCE AND TARGET
        -----------------
        Source IP: {incident.get('source_ip', 'Unknown')}
        Target host: {incident.get('target_agent', 'Unknown')}

        TIMELINE
        --------
        First seen: {incident.get('first_seen', 'Unknown')}
        Last seen: {incident.get('last_seen', 'Unknown')}

        DETECTION DETAILS
        -----------------
        Alerts: {incident.get('alert_count', 0)}
        Distinct URLs: {incident.get('distinct_urls', 0)}
        Wazuh rules: {', '.join(incident.get('rule_ids', []))}
        HTTP statuses: {', '.join(incident.get('http_statuses', []))}

        Risk score reasons:
        {reason_text}

        SAMPLE REQUESTED URLS
        ---------------------
        {url_text}

        RECOMMENDED ACTIONS
        -------------------
        1. Investigate the source IP and request timeline.
        2. Verify whether the source was blocked by active response.
        3. Review the targeted paths and investigate any successful requests.

        This report was generated automatically by the Python
        Incident Context Engine.
        """

    return subject, body


def main():
    password = getpass.getpass("Wazuh Indexer admin password: ")

    session = requests.Session()
    session.auth = ("admin", password)
    session.verify = False

    processed_ids = load_json(STATE_FILE, [])
    processed_ids = set(processed_ids)

    incidents = load_json(INCIDENT_FILE, [])

    logging.info("Real-time incident engine started.")
    print("engine_started....1")

    try:
        while True:
            try:
                new_alerts = fetch_new_alerts(
                    session,
                    processed_ids
                )

                for hit in new_alerts:
                    alert = hit.get("_source", {})
                    process_alert(alert, incidents)
                    processed_ids.add(hit["_id"])

                if new_alerts:
                    for incident in incidents:
                        if (
                            incident.get("risk_score", 0) >= 30
                            and not incident.get("email_sent", False)
                        ):
                            subject, body = build_incident_email(incident)

                            try:
                                send_email_notification(
                                    "zerwalihassan111@gmail.com",
                                    subject,
                                    body
                                )

                                incident["email_sent"] = True

                            except Exception:
                                logging.exception(
                                    "Email notification failed for %s",
                                    incident.get("incident_id")
                                )

                    save_json(INCIDENT_FILE, incidents)
                    save_json(STATE_FILE, sorted(processed_ids))

                    logging.info(
                        "Processed %s new alerts. Total incidents: %s",
                        len(new_alerts),
                        len(incidents)
                    )

                time.sleep(POLL_INTERVAL)

            except requests.RequestException as error:
                logging.error("Indexer connection error: %s", error)
                time.sleep(POLL_INTERVAL)

            except (ValueError, KeyError, TypeError) as error:
                logging.exception("Alert processing error: %s", error)
                time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        logging.info("Monitoring stopped.")

    finally:
        session.close()


if __name__ == "__main__":
    main()
