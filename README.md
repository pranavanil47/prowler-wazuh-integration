# 🚀 Prowler → Wazuh → DFIR-IRIS Integration
End-to-end Cloud Security Detection, Enrichment & Case Automation

This project connects AWS Prowler → Wazuh SIEM → DFIR-IRIS Case Management with automated ingestion, decoding, alerting, deduplication, and case creation.

---

## 📌 **What’s New (Updated Integration 2025)**
✔ Fully automated pipeline: **Prowler → S3 → Wazuh → IRIS**  
✔ Custom integration script for **case creation in IRIS**  
✔ Wazuh → IRIS severity mapping  
✔ MITRE ATT&CK enrichment  
✔ Dedupe DB to prevent duplicate case creation  
✔ Supports OCSF JSON format  
✔ Ready to deploy in production

---

## 📁 Project Structure
```
prowler-wazuh-integration/
│
├── scripts/
│   ├── run_prowler.sh                 # Runs Prowler OCSF scan → Uploads to S3
│   ├── pull_prowler_from_s3.sh        # Sync script to pull logs → Wazuh
│
├── wazuh-config/
│   ├── ossec.conf                     # Reads Prowler OCSF log file
│   ├── decoders/
│   │   └── prowler_decoders.xml       # Extracts fields from OCSF JSON
│   └── rules/
│       └── prowler_rules.xml          # Alerts Wazuh on Prowler findings
│
├── integrations/
│   └── custom-iris                    # Wazuh → DFIR-IRIS integration
│       (Python script to create IRIS cases)
│
├── dashboards/
│   └── wazuh_pie_severity.ndjson      # Kibana/Opensearch dashboard
│
└── README.md
```

---

## 🔄 **Pipeline Overview**

### **1. Prowler Scan (run_prowler.sh)**
- Runs Prowler in **JSON-OCSF** format  
- Uploads results to your S3 bucket  
- Supports multi-account scans

### **2. Log Sync (pull_prowler_from_s3.sh)**
- Downloads new Prowler OCSF files  
- Appends them to:
  ```
  /var/ossec/logs/prowler/prowler-ocsf.log
  ```
- Deletes processed S3 files  
- Ensures **zero duplicate ingestion**

### **3. Wazuh Localfile Configuration**
Wazuh monitors the consolidated Prowler log file:
```
<localfile>
  <location>/var/ossec/logs/prowler/prowler-ocsf.log</location>
  <log_format>json</log_format>
</localfile>
```

### **4. Custom Decoders**
Extracts:
- check_id  
- severity  
- resource  
- region  
- remediation  
- account ID  
- provider information  
- OCSF fields

### **5. Prowler Rules**
Generates alerts with:
- Rule ID: 110005 (for OCSF)  
- Severity mapped to Prowler severity

### **6. DFIR-IRIS Integration (custom-iris)**  
- Triggered by Wazuh integrator  
- Deduplicates using SQLite DB  
- Creates IRIS **cases** via API  
- Severity auto-mapped from Wazuh rule level  
- Includes MITRE, agent details, raw logs  
- Works with Bearer token auth  

**Example API used:**
```
POST https://<iris-url>/api/v1/cases
Authorization: Bearer <token>
```

---

## 📊 Dashboards

Included `wazuh_pie_severity.ndjson` for:
- Prowler Severity Distribution  
- High-Risk Findings Over Time  
- Resource Grouping  
- Account-wise Findings  

Import directly into Kibana / OpenSearch Dashboards.

---

## ⚙️ Requirements

### AWS
- IAM role with:
  - `s3:PutObject`
  - `s3:GetObject`
  - `s3:DeleteObject`

### Wazuh
- Version 4.14+  
- Python3 integration support  
- AWS CLI installed

### IRIS
- DFIR-IRIS v2.4.24+  
- API Token (Bearer recommended)

---

## 🔐 Environment Variables (optional for production)
```
IRIS_API_URL="https://<iris>/api/v1/cases"
IRIS_API_KEY="<your-token>"
IRIS_API_AUTH_TYPE="bearer"
VERIFY_TLS="false"
DEDUPE_DB_PATH="/var/ossec/queue/iris_dedupe.db"
DEDUPE_RETENTION_DAYS=30
```

---

## 🙌 Thanks
Project maintained by **Pranav**  
Cybersecurity Student • Cloud Security • SOC Automation  

---

