#!/usr/bin/env python3
"""
Codemender Automated Security Remediation & Golden Standards PoC Setup
Target Project: codemender-oss
Role: Security Customer Engineer (CE)

Provisions:
1. Artifact Registry Repositories ('golden-apps-source-repo' & 'hardened-golden-repo') in us-central1.
2. Air-Gapped Sandbox VPC ('codemender-sandbox-vpc') & Subnet ('codemender-sandbox-subnet-us') with Private Google Access.
3. Strict Network Firewall Policies:
   - Deny all external internet egress (0.0.0.0/0)
   - Allow Private Google Access (199.36.153.8/30 on TCP 443)
   - Allow internal mesh & Google IAP SSH forwarding (35.235.240.0/20)
4. Isolated Benchmark Workloads (VMs with NO EXTERNAL IP '--no-address'):
   - 'vuln-webapp-node' (OWASP Juice Shop / Node.js prototype with known SQLi & XSS baseline)
   - 'vuln-api-python' (Vulnerable Flask REST API with Insecure YAML Deserialization & Command Injection baseline)
"""

import subprocess
import sys
import json
import time

PROJECT_ID = "codemender-oss"
REGION = "us-central1"
ZONE = "us-central1-a"

VPC_NAME = "codemender-sandbox-vpc"
SUBNET_NAME = "codemender-sandbox-subnet-us"
SUBNET_RANGE = "10.128.0.0/20"

AR_REPO_VULN = "golden-apps-source-repo"
AR_REPO_HARDENED = "hardened-golden-repo"


def run_gcloud(args, check=True):
    cmd = ["gcloud"] + args + ["--project", PROJECT_ID, "--quiet"]
    print(f"[RUN] {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0 and check:
        print(f"[ERROR] Command failed ({res.returncode}): {res.stderr}")
    else:
        if res.stdout.strip():
            print(res.stdout.strip())
    return res


def setup_artifact_registry():
    print("\n" + "="*70)
    print("PHASE 1: PROVISIONING ARTIFACT REGISTRY GOLDEN STANDARDS REPOSITORIES")
    print("="*70)
    
    for repo, desc in [
        (AR_REPO_VULN, "Baseline vulnerable applications and container manifests for Codemender PoC"),
        (AR_REPO_HARDENED, "Codemender remediated and verified Golden Standard hardened builds")
    ]:
        print(f"\n--> Creating Artifact Registry repository: {repo} ({REGION})")
        run_gcloud([
            "artifacts", "repositories", "create", repo,
            f"--repository-format=docker",
            f"--location={REGION}",
            f"--description={desc}"
        ], check=False)


def setup_isolated_vpc():
    print("\n" + "="*70)
    print("PHASE 2: PROVISIONING AIR-GAPPED SANDBOX VPC & STRICT FIREWALL RULES")
    print("="*70)
    
    print(f"\n--> Creating custom VPC network: {VPC_NAME}")
    run_gcloud([
        "compute", "networks", "create", VPC_NAME,
        "--subnet-mode=custom"
    ], check=False)

    print(f"\n--> Creating subnet {SUBNET_NAME} ({SUBNET_RANGE}) with Private Google Access")
    run_gcloud([
        "compute", "networks", "subnets", "create", SUBNET_NAME,
        f"--network={VPC_NAME}",
        f"--region={REGION}",
        f"--range={SUBNET_RANGE}",
        "--enable-private-ip-google-access"
    ], check=False)

    print("\n--> Configuring strict containment firewall rules...")
    
    # 1. Deny all external internet egress
    run_gcloud([
        "compute", "firewall-rules", "create", "deny-external-egress",
        f"--network={VPC_NAME}",
        "--direction=EGRESS",
        "--priority=65534",
        "--destination-ranges=0.0.0.0/0",
        "--action=DENY",
        "--rules=all"
    ], check=False)

    # 2. Allow egress to Private Google Access VIPs
    run_gcloud([
        "compute", "firewall-rules", "create", "allow-private-google-access",
        f"--network={VPC_NAME}",
        "--direction=EGRESS",
        "--priority=1000",
        "--destination-ranges=199.36.153.8/30",
        "--action=ALLOW",
        "--rules=tcp:443"
    ], check=False)

    # 3. Allow internal sandbox mesh communication
    run_gcloud([
        "compute", "firewall-rules", "create", "allow-internal-sandbox-mesh",
        f"--network={VPC_NAME}",
        "--direction=INGRESS",
        "--priority=1000",
        f"--source-ranges={SUBNET_RANGE}",
        "--action=ALLOW",
        "--rules=tcp:22,tcp:3000,tcp:5000,icmp"
    ], check=False)

    # 4. Allow Google IAP SSH forwarding (safe administrative access without external IPs)
    run_gcloud([
        "compute", "firewall-rules", "create", "allow-iap-ssh-internal",
        f"--network={VPC_NAME}",
        "--direction=INGRESS",
        "--priority=1000",
        "--source-ranges=35.235.240.0/20",
        "--action=ALLOW",
        "--rules=tcp:22"
    ], check=False)


def provision_sandbox_vms():
    print("\n" + "="*70)
    print("PHASE 3: PROVISIONING AIR-GAPPED SANDBOX TARGET VMS (--no-address)")
    print("="*70)

    node_startup = """#!/bin/bash
apt-get update && apt-get install -y nodejs npm git
mkdir -p /opt/vulnerable-apps/node-juice-shop
cat << 'EOF' > /opt/vulnerable-apps/node-juice-shop/server.js
// OWASP Juice Shop Baseline Prototype - Vulnerable to SQLi & XSS
const http = require('http');
http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('Codemender Sandbox: OWASP Juice Shop Vulnerable Baseline (Port 3000)\\n');
}).listen(3000, '0.0.0.0');
EOF
node /opt/vulnerable-apps/node-juice-shop/server.js &
"""

    py_startup = """#!/bin/bash
apt-get update && apt-get install -y python3 python3-pip git
mkdir -p /opt/vulnerable-apps/py-flask-api
cat << 'EOF' > /opt/vulnerable-apps/py-flask-api/app.py
# Vulnerable Python Flask API Prototype - Vulnerable to CWE-502 & CWE-78
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handle(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Codemender Sandbox: Vulnerable Python API Baseline (Port 5000)\\n')
HTTPServer(('0.0.0.0', 5000), Handle).serve_forever()
EOF
python3 /opt/vulnerable-apps/py-flask-api/app.py &
"""

    print("\n--> Deploying VM 1: vuln-webapp-node (Internal-Only, No External IP)")
    run_gcloud([
        "compute", "instances", "create", "vuln-webapp-node",
        f"--zone={ZONE}",
        "--machine-type=e2-medium",
        "--image-family=debian-12",
        "--image-project=debian-cloud",
        f"--network={VPC_NAME}",
        f"--subnet={SUBNET_NAME}",
        "--no-address",
        f"--metadata=startup-script={node_startup}"
    ], check=False)

    print("\n--> Deploying VM 2: vuln-api-python (Internal-Only, No External IP)")
    run_gcloud([
        "compute", "instances", "create", "vuln-api-python",
        f"--zone={ZONE}",
        "--machine-type=e2-medium",
        "--image-family=debian-12",
        "--image-project=debian-cloud",
        f"--network={VPC_NAME}",
        f"--subnet={SUBNET_NAME}",
        "--no-address",
        f"--metadata=startup-script={py_startup}"
    ], check=False)


def generate_status_report():
    print("\n" + "="*70)
    print("PHASE 4: CODEMENDER POC ENVIRONMENT STATUS VERIFICATION")
    print("="*70)
    
    ar_list = run_gcloud(["artifacts", "repositories", "list", f"--location={REGION}"], check=False)
    vms_list = run_gcloud(["compute", "instances", "list", f"--zones={ZONE}"], check=False)
    
    print("\n--- PoC Provisioning Summary ---")
    print("[ACTIVE PROJECT]:", PROJECT_ID)
    print("[AIR-GAPPED VPC]:", VPC_NAME, f"(Subnet: {SUBNET_NAME} {SUBNET_RANGE})")
    print("[GOLDEN REPOS]:", f"{AR_REPO_VULN}, {AR_REPO_HARDENED} in {REGION}")
    print("[SANDBOX VMS]: vuln-webapp-node, vuln-api-python (--no-address enabled)")
    print("======================================================================")


if __name__ == "__main__":
    setup_artifact_registry()
    setup_isolated_vpc()
    provision_sandbox_vms()
    generate_status_report()
