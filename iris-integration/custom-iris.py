#!/var/ossec/framework/python/bin/python3
# custom-wazuh_iris.py
# Custom Wazuh integration script to send alerts to DFIR-IRIS
# Updated to support Prowler OCSF v1.5 JSON output

import sys
import json
import requests
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='/var/ossec/logs/integrations.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def get_prowler_data(alert_json):
    """Extracts Prowler specific data from Wazuh 'data' block or 'full_log'."""
    data = alert_json.get("data", {})
    full_log_str = alert_json.get("full_log")

    prowler_info = {
        'is_prowler': False,
        'compliance': {}
    }

    # 1. Try parsing 'data' block (Wazuh decoder output)
    # Your sample uses 'finding_info' (OCSF 1.5), not 'finding'
    if "finding_info" in data:
        prowler_info['is_prowler'] = True
        prowler_info['title'] = data.get("finding_info", {}).get("title")
        prowler_info['description'] = data.get("finding_info", {}).get("desc")
        prowler_info['uid'] = data.get("finding_info", {}).get("uid") # Unique finding ID

        # Severity
        prowler_info['severity'] = data.get("severity", "Unknown")

        # Status
        prowler_info['status'] = data.get("status", "Unknown")
        prowler_info['status_detail'] = data.get("status_detail")

        # Cloud / Region / Account
        prowler_info['region'] = data.get("cloud", {}).get("region")
        prowler_info['provider'] = data.get("cloud", {}).get("provider")
        prowler_info['account'] = data.get("cloud", {}).get("account", {}).get("uid")

        # Resources (OCSF uses a list)
        resources = data.get("resources", [])
        if isinstance(resources, list) and len(resources) > 0:
            res = resources[0]
            prowler_info['resource_uid'] = res.get("uid")
            prowler_info['resource_type'] = res.get("type")
            # Try to dig deeper for metadata id if available
            if "data" in res and "metadata" in res["data"]:
                prowler_info['resource_id'] = res["data"]["metadata"].get("id")

        # Remediation
        prowler_info['remediation'] = data.get("remediation", {}).get("desc")
        prowler_info['references'] = data.get("remediation", {}).get("references", [])

        # Compliance (in 'unmapped')
        prowler_info['compliance'] = data.get("unmapped", {}).get("compliance", {})

    # 2. Fallback: If 'data' is empty/incomplete, try parsing 'full_log' manually
    elif full_log_str:
        try:
            # Sometimes full_log is the raw JSON line from Prowler
            fl_json = json.loads(full_log_str)
            if "finding_info" in fl_json:
                prowler_info['is_prowler'] = True
                prowler_info['title'] = fl_json.get("finding_info", {}).get("title")
                prowler_info['description'] = fl_json.get("finding_info", {}).get("desc")
                prowler_info['uid'] = fl_json.get("finding_info", {}).get("uid")
                prowler_info['severity'] = fl_json.get("severity")
                prowler_info['status'] = fl_json.get("status")
                prowler_info['status_detail'] = fl_json.get("status_detail")
                prowler_info['region'] = fl_json.get("cloud", {}).get("region")
                prowler_info['account'] = fl_json.get("cloud", {}).get("account", {}).get("uid")

                resources = fl_json.get("resources", [])
                if resources:
                    prowler_info['resource_uid'] = resources[0].get("uid")

                prowler_info['remediation'] = fl_json.get("remediation", {}).get("desc")
                prowler_info['references'] = fl_json.get("remediation", {}).get("references", [])
                prowler_info['compliance'] = fl_json.get("unmapped", {}).get("compliance", {})
        except json.JSONDecodeError:
            pass

    return prowler_info

def format_alert_details(alert_json, prowler_data):
    rule = alert_json.get("rule", {})
    agent = alert_json.get("agent", {})

    # Standard Header
    details = [
        "### Wazuh Alert Info",
        f"**Rule ID:** {rule.get('id', 'N/A')}",
        f"**Agent:** {agent.get('name', 'N/A')} ({agent.get('id', 'N/A')})",
        ""
    ]

    if prowler_data.get('is_prowler'):
        # Core Findings
        details.extend([
            "### Prowler Finding Analysis",
            f"**Finding:** {prowler_data.get('title')}",
            f"**Severity:** {prowler_data.get('severity')}",
            f"**Status:** {prowler_data.get('status')} ({prowler_data.get('status_detail', '')})",
            "",
            "### Cloud Context",
            f"**Provider:** {prowler_data.get('provider', 'AWS')}",
            f"**Account ID:** {prowler_data.get('account', 'N/A')}",
            f"**Region:** {prowler_data.get('region', 'N/A')}",
            f"**Resource UID:** {prowler_data.get('resource_uid', 'N/A')}",
        ])

        # Compliance Section
        if prowler_data.get('compliance'):
            details.append("")
            details.append("### Compliance Impact")
            for framework, reqs in prowler_data['compliance'].items():
                # reqs might be a list or string
                req_str = ", ".join(reqs) if isinstance(reqs, list) else str(reqs)
                details.append(f"- **{framework}:** {req_str}")

        # Remediation Section
        details.append("")
        details.append("### Remediation")
        details.append(f"{prowler_data.get('remediation', 'No remediation steps provided.')}")

        if prowler_data.get('references'):
            details.append("")
            details.append("**References:**")
            for ref in prowler_data['references']:
                details.append(f"- {ref}")

    else:
        # Fallback for non-Prowler alerts
        details.append(f"**Full Log:** {alert_json.get('full_log', 'N/A')}")

    return '\n'.join(details)

def map_severity(wazuh_level, prowler_severity=None):
    """Maps Wazuh level or Prowler severity label to IRIS severity ID (1-6)."""
    # IRIS: 1:Info, 2:Low, 3:Medium, 4:High, 5:Critical, 6:Fatal

    if prowler_severity:
        s = str(prowler_severity).lower()
        if "critical" in s: return 6
        if "high" in s: return 4
        if "medium" in s: return 3
        if "low" in s: return 2
        if "info" in s: return 1

    # Fallback to numeric Wazuh level
    try:
        level = int(wazuh_level)
        if level < 5: return 2
        if 5 <= level < 7: return 3
        if 7 <= level < 10: return 4
        if 10 <= level < 13: return 5
        if level >= 13: return 6
    except:
        pass
    return 2 # Default Low

def main():
    if len(sys.argv) < 4:
        logging.error("Insufficient arguments provided. Exiting.")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    try:
        with open(alert_file) as f:
            alert_json = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read alert file: {e}")
        sys.exit(1)

    # Extract Data
    prowler_data = get_prowler_data(alert_json)

    # Title: Use Prowler title + Account ID for context
    if prowler_data.get('is_prowler') and prowler_data.get('title'):
        alert_title = f"Prowler: {prowler_data.get('title')}"
    else:
        alert_title = alert_json.get("rule", {}).get("description", "Wazuh Alert")

    # Description
    alert_description = format_alert_details(alert_json, prowler_data)

    # Severity
    wazuh_level = alert_json.get("rule", {}).get("level", 0)
    severity_id = map_severity(wazuh_level, prowler_data.get('severity'))

    # Unique Reference (Crucial for avoiding dupes if IRIS supports it)
    # Use Prowler finding UID if available, else Wazuh Alert ID
    source_ref = prowler_data.get('uid') if prowler_data.get('uid') else alert_json.get("id")

    # Build Payload
    payload = json.dumps({
        "alert_title": alert_title,
        "alert_description": alert_description,
        "alert_source": "Wazuh",
        "alert_source_ref": source_ref,
        "alert_severity_id": severity_id,
        "alert_status_id": 2,  # New
        "alert_source_event_time": alert_json.get("timestamp", datetime.now().isoformat()),
        "alert_note": f"Account: {prowler_data.get('account', 'N/A')} | Region: {prowler_data.get('region', 'N/A')}",
        "alert_tags": f"wazuh,prowler,aws,{prowler_data.get('provider', 'cloud')}",
        "alert_customer_id": 1,
        "alert_source_content": alert_json
    })

    try:
        response = requests.post(
            hook_url,
            data=payload,
            headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"},
            verify=False
        )

        if response.status_code in [200, 201, 202, 204]:
            logging.info(f"Sent alert to IRIS. Response: {response.status_code}")
        else:
            logging.error(f"Failed to send to IRIS. Code: {response.status_code}, Body: {response.text}")

    except Exception as e:
        logging.error(f"Failed to send alert to IRIS: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()