# Gemini Enterprise Employee Database & Model Armor High-Confidence Security Suite

Project: `manufacturing-demo-486618`  
Application ID: `employee-database-ge-app`  
Model Armor Template ID: `ge-employee-db-armor-high`

## Architecture & Overview

This solution deploys a **Gemini Enterprise (Discovery Engine) Chat/Search Application** that serves as an **Employee Database** for `manufacturing-demo-486618`, wrapped with two critical security layers:

1. **Content Policy (User Flow Upload Blocker)**:
   - Enforces `BLOCK_FILE_UPLOADS_TO_GE` (`allowFileUploads: false`).
   - Prevents users from uploading external documents or files in the employee query flow to protect against untrusted document ingestion and data exfiltration.

2. **Model Armor AI Firewall Template (High Confidence Defaults)**:
   - Configures all default safety filters at the **HIGH CONFIDENCE** (`HIGH_CONFIDENT`) threshold:
     - Prompt Injection (`HIGH`)
     - PII / Sensitive Data Protection (`HIGH`)
     - Malicious URIs (`HIGH`)
     - Hate Speech (`HIGH`)
     - Harassment (`HIGH`)
     - Sexually Explicit Content (`HIGH`)
     - Dangerous Content (`HIGH`)

---

## Directory Contents

- [`ge_model_armor_config.json`](file:///usr/local/google/home/mikadevonshire/Projects/TestProj/nerc-project/ge_model_armor_config.json): Canonical JSON configuration schema defining the Model Armor Template and Gemini Enterprise App Content Policy.
- [`provision_ge_app.py`](file:///usr/local/google/home/mikadevonshire/Projects/TestProj/nerc-project/provision_ge_app.py): Python script to validate and provision the Model Armor Template and Gemini Enterprise App in project `manufacturing-demo-486618`.
- [`server.py`](file:///usr/local/google/home/mikadevonshire/Projects/TestProj/nerc-project/server.py): Secure backend server & simulator running on `http://127.0.0.1:8092` with live Content Policy upload blocking and Model Armor prompt inspection.
- [`public/`](file:///usr/local/google/home/mikadevonshire/Projects/TestProj/nerc-project/public/index.html): Interactive dark glassmorphism web portal showcasing the Employee Directory, GE User Flow Sandbox, and Model Armor Inspector.

---

## Quickstart

### 1. Verify Configuration & Generate Provisioning Manifest
```bash
python3 provision_ge_app.py
```

### 2. Launch Interactive Employee Database Portal & Security Sandbox
```bash
python3 server.py
```
Open `http://127.0.0.1:8092` in your browser to interactively test employee database queries and observe inline file-upload blocking and Model Armor prompt filtering.
