# Prowler to Wazuh Integration

Automated flow from AWS Prowler → S3 Bucket → Wazuh SIEM for cloud security visibility. Includes custom decoder, rules, and illustrative dashboards.

---

## 🚀 Features

- Prowler results in JSON-OCSF
- S3 storage + Wazuh AWS sync
- No duplicate log processing
- Custom Wazuh decoding and alerting
- Automated ingestion pipeline
- Dashboards for visibility

---

## 🧰 Setup

### Prerequisites
- AWS CLI with credentials
- Wazuh Manager 4.14+
- Prowler 5.13.1+
- `aws` and `jq` installed

### Files Structure

prowler-wazuh-integration/
├── scripts/
│ ├── run_prowler.sh # Runs Prowler and uploads to S3
│ ├── pull_prowler_from_s3.sh # Downloads & cleans local logs
├── wazuh-config/
│ ├── ossec.conf # Wazuh local file reading config
│ └── decoders/prowler_decoders.xml
│ └── rules/prowler_rules.xml
├── dashboards/wazuh_pie_severity.ndjson
└── README.md

Thankyou 
Pranav 
