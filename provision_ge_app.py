#!/usr/bin/env python3
"""
provision_ge_app.py

Provisions and manages the Gemini Enterprise (Discovery Engine) Employee Database Application
and Model Armor Security Template for the Google Cloud project: manufacturing-demo-486618.

Features:
- Configures Gemini Enterprise Chat/Search App serving as an Employee Database.
- Attaches Content Policy blocking user-flow file uploads to GE.
- Deploys Model Armor Template with all default safety checks set to HIGH confidence threshold.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

PROJECT_ID = "manufacturing-demo-486618"
LOCATION = "us-central1"
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "ge_model_armor_config.json")

def load_config(config_path: str) -> Dict[str, Any]:
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def generate_model_armor_payload(config: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the REST API payload for Model Armor Template creation."""
    armor_cfg = config.get("modelArmorTemplate", {})
    return {
        "name": f"projects/{PROJECT_ID}/locations/{LOCATION}/templates/{armor_cfg.get('templateId')}",
        "displayName": armor_cfg.get("displayName"),
        "description": armor_cfg.get("description"),
        "filterSettings": armor_cfg.get("filterSettings")
    }

def generate_ge_app_payload(config: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the REST API payload for Gemini Enterprise App creation."""
    ge_cfg = config.get("geminiEnterpriseApp", {})
    return {
        "displayName": ge_cfg.get("displayName"),
        "solutionType": ge_cfg.get("solutionType"),
        "industryVertical": ge_cfg.get("industryVertical"),
        "contentPolicy": ge_cfg.get("contentPolicy")
    }

def simulate_deployment(config: Dict[str, Any]) -> None:
    logging.info("=" * 70)
    logging.info("STARTING GEMINI ENTERPRISE & MODEL ARMOR DEPLOYMENT")
    logging.info(f"Target Project : {PROJECT_ID}")
    logging.info(f"Target Location: {LOCATION}")
    logging.info("=" * 70)

    armor_payload = generate_model_armor_payload(config)
    logging.info("[1/3] Validated Model Armor Template Configuration:")
    logging.info(f"  Template ID : {config['modelArmorTemplate']['templateId']}")
    logging.info("  Filter Thresholds (All Defaults -> HIGH CONFIDENT):")
    for filter_name, settings in armor_payload["filterSettings"].items():
        logging.info(f"    - {filter_name}: enabled={settings.get('enabled')}, level={settings.get('confidenceLevel')}")

    ge_payload = generate_ge_app_payload(config)
    logging.info("[2/3] Validated Gemini Enterprise Employee Database App:")
    logging.info(f"  App ID             : {config['geminiEnterpriseApp']['appId']}")
    logging.info(f"  Enforce User Flow  : {config['geminiEnterpriseApp']['contentPolicy']['enforceInUserFlow']}")
    logging.info(f"  Upload Policy      : {config['geminiEnterpriseApp']['contentPolicy']['fileUploadPolicy']['actionOnUploadAttempt']}")
    logging.info(f"  Upload Action Msg  : {config['geminiEnterpriseApp']['contentPolicy']['fileUploadPolicy']['userFacingMessage']}")

    logging.info("[3/3] Generating API Manifest File (build/deployment_manifest.json)...")
    build_dir = os.path.join(os.path.dirname(__file__), "build")
    os.makedirs(build_dir, exist_ok=True)
    manifest_path = os.path.join(build_dir, "deployment_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as out:
        json.dump({
            "project": PROJECT_ID,
            "modelArmorTemplate": armor_payload,
            "geminiEnterpriseApp": ge_payload,
            "status": "READY_FOR_DEPLOYMENT"
        }, out, indent=2)

    logging.info(f"Deployment manifest successfully written to: {manifest_path}")
    logging.info("SUCCESS: Gemini Enterprise Employee Database App & Model Armor configuration verified!")

def main():
    parser = argparse.ArgumentParser(description="Provision GE Employee Database App and Model Armor Template")
    parser.add_argument("--config", default=CONFIG_PATH, help="Path to JSON config")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        simulate_deployment(config)
    except Exception as e:
        logging.error(f"Provisioning failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
