#!/usr/bin/env python3
"""
server.py - Secure Local Backend & Simulator for Gemini Enterprise Employee Database Portal.

Follows mandatory secure coding guidelines:
- Strict CSP and Security Headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY)
- PII Masking applied on employee database records
- Inline Content Policy enforcement blocking all file upload attempts in user query flow
- Model Armor inline prompt & response inspection simulator with HIGH confidence thresholds
- Server listens strictly on localhost (127.0.0.1)
"""

import json
import logging
import os
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

HOST = "127.0.0.1"
PORT = 8092
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

# Mock Employee Database with Masked PII per secure coding guidelines
EMPLOYEES = [
    {
        "id": "EMP-1042",
        "name": "Elena Rostova",
        "role": "Principal Manufacturing Automation Lead",
        "department": "Robotics & PLC",
        "location": "Zurich Plant (CH-01)",
        "clearance": "Top Secret / Tier 5",
        "email": "e.rostova@manufacturing-demo-486618.internal",
        "ssnMasked": "***-**-4291",
        "status": "Active"
    },
    {
        "id": "EMP-1088",
        "name": "Marcus Vance",
        "role": "Senior Industrial Security Specialist",
        "department": "OT Security & Armor",
        "location": "Austin Facility (US-TX)",
        "clearance": "Secret / Tier 3",
        "email": "m.vance@manufacturing-demo-486618.internal",
        "ssnMasked": "***-**-8819",
        "status": "Active"
    },
    {
        "id": "EMP-1123",
        "name": "Aria Chen",
        "role": "Director of Supply Chain Analytics",
        "department": "Operations",
        "location": "Singapore Hub (SG-HQ)",
        "clearance": "Top Secret / Tier 5",
        "email": "a.chen@manufacturing-demo-486618.internal",
        "ssnMasked": "***-**-1104",
        "status": "Active"
    },
    {
        "id": "EMP-1195",
        "name": "Dr. Viktor Thorne",
        "role": "Chief Metallurgical Engineer",
        "department": "Materials R&D",
        "location": "Munich Lab (DE-02)",
        "clearance": "Top Secret / Tier 5",
        "email": "v.thorne@manufacturing-demo-486618.internal",
        "ssnMasked": "***-**-9541",
        "status": "On Leave"
    },
    {
        "id": "EMP-1240",
        "name": "Samantha Kael",
        "role": "Quality Assurance Specialist",
        "department": "Quality Control",
        "location": "Austin Facility (US-TX)",
        "clearance": "Confidential / Tier 1",
        "email": "s.kael@manufacturing-demo-486618.internal",
        "ssnMasked": "***-**-3312",
        "status": "Active"
    }
]

def load_ge_config() -> dict:
    cfg_path = os.path.join(BASE_DIR, "ge_model_armor_config.json")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

class SecureGEPortalHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def end_headers(self):
        # Mandatory Security Headers
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/config":
            self.send_json_response(200, load_ge_config())
            return
        elif parsed.path == "/api/employees":
            query = parse_qs(parsed.query).get("q", [""])[0].lower().strip()
            if not query:
                self.send_json_response(200, {"employees": EMPLOYEES, "count": len(EMPLOYEES)})
            else:
                filtered = [
                    emp for emp in EMPLOYEES
                    if query in emp["name"].lower() or query in emp["role"].lower()
                    or query in emp["department"].lower() or query in emp["location"].lower()
                ]
                self.send_json_response(200, {"employees": filtered, "count": len(filtered)})
            return
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"

        try:
            payload = json.loads(raw_body)
        except Exception:
            self.send_json_response(400, {"error": "Invalid JSON payload"})
            return

        if parsed.path == "/api/ge/query":
            prompt = payload.get("prompt", "")
            has_file_upload = payload.get("hasFileUpload", False)
            uploaded_filename = payload.get("filename", "")

            # 1. Content Policy Check: Block file uploads in user flow
            if has_file_upload:
                logging.warning(f"[GE CONTENT POLICY ENFORCED] Blocked upload attempt: '{uploaded_filename}'")
                self.send_json_response(403, {
                    "blocked": True,
                    "reason": "CONTENT_POLICY_VIOLATION",
                    "policyName": "ge-employee-db-content-policy",
                    "enforcementAction": "BLOCK_AND_LOG",
                    "message": "Blocked by GE Content Policy: File uploads are disabled for Employee Database queries to prevent unauthorized data ingestion and PII leakage.",
                    "details": f"Attempted file '{uploaded_filename}' rejected by user flow upload firewall."
                })
                return

            # 2. Model Armor Inspection Simulation (High Confidence)
            lower_prompt = prompt.lower()
            harmful_patterns = ["ignore previous instructions", "jailbreak", "dump all ssn", "system prompt", "bypass armor"]
            for pattern in harmful_patterns:
                if pattern in lower_prompt:
                    logging.warning(f"[MODEL ARMOR BLOCKED] Prompt injection / malicious query detected: '{pattern}'")
                    self.send_json_response(403, {
                        "blocked": True,
                        "reason": "MODEL_ARMOR_HIGH_CONFIDENT_VIOLATION",
                        "policyName": "ge-employee-db-armor-high",
                        "enforcementAction": "BLOCK",
                        "message": "Blocked by Model Armor (HIGH confidence threshold): Prompt injection or unauthorized bulk PII exfiltration signature detected."
                    })
                    return

            # 3. Process Natural Language Query against Employee Database
            results = []
            for emp in EMPLOYEES:
                if any(word in emp["name"].lower() or word in emp["department"].lower() or word in emp["role"].lower() for word in lower_prompt.split()):
                    results.append(emp)
            if not results:
                results = EMPLOYEES[:3] # Default suggested profiles

            self.send_json_response(200, {
                "blocked": False,
                "modelArmorStatus": "PASSED (All 7 filters evaluated at HIGH threshold)",
                "contentPolicyStatus": "PASSED (No external files in flow)",
                "answer": f"Found {len(results)} employee profile(s) relevant to your query in manufacturing-demo-486618.",
                "matchedEmployees": results
            })
            return

        self.send_json_response(404, {"error": "Endpoint not found"})

    def send_json_response(self, status: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    server = HTTPServer((HOST, PORT), SecureGEPortalHandler)
    logging.info(f"Gemini Enterprise Employee Database Server running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Server stopped.")
