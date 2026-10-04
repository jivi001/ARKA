#!/usr/bin/env python3
"""
ARKA Security Foundation — Threat Model & Model Integrity Validator
Enforces schema validation, referential integrity, stable ID compliance,
and required threat model coverage for P0 Checkpoint validation.
"""

import sys
import os
import json
import hashlib
import yaml
import jsonschema

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCHEMAS_DIR = os.path.join(BASE_DIR, "threat-model", "schemas")
THREAT_MODEL_DIR = os.path.join(BASE_DIR, "threat-model")

MANDATORY_TRD_THREATS = [
    "malicious_target_content",
    "prompt_injection",
    "tool_output_poisoning",
    "rogue_agent",
    "forged_a2a_message",
    "token_theft",
    "replay",
    "scope_expansion",
    "ssrf",
    "dns_rebinding",
    "credential_theft",
    "sandbox_escape",
    "host_compromise",
    "cross_mission_leakage",
    "audit_tampering",
    "evidence_tampering",
    "resource_exhaustion",
    "llm_provider_exposure",
    "dependency_compromise",
    "operator_misuse",
]

MANDATORY_ADDITIONAL_THREATS = [
    "toctou_parameter_mutation",
    "emergency_stop_bypass",
    "evidence_parser_compromise",
    "graphify_poisoning",
    "llm_egress_data_leakage",
    "ci_gate_manipulation",
    "ci_supply_chain_compromise",
]

VALID_INVARIANTS = {
    f"INV-{i:03d}" for i in range(1, 17)
}

VALID_COMPONENTS = {
    "COMP-KERNEL",
    "COMP-AUTH",
    "COMP-SCOPE",
    "COMP-NORM",
    "COMP-APPROV",
    "COMP-BROKER",
    "COMP-WORKER",
    "COMP-SANDBOX",
    "COMP-INTEL",
    "COMP-LLM-GW",
    "COMP-EVID",
    "COMP-CRED",
    "COMP-AUDIT",
    "COMP-RES-GOV",
    "COMP-ESTOP",
    "COMP-KG",
    "COMP-UI",
    "COMP-CI",
}

def load_yaml(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Missing required file: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_json(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Missing required schema: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def compute_file_sha256(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def validate_schema(data, schema_file, item_name):
    schema = load_json(schema_file)
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
    if errors:
        print(f"[-] Schema validation failed for {item_name}:")
        for err in errors:
            path = ".".join(str(p) for p in err.path)
            print(f"    - [{path}]: {err.message}")
        return False
    print(f"[+] Schema validation passed: {item_name}")
    return True

def run_validation():
    print("================================================================================")
    print("                ARKA P0 SECURITY MODEL VALIDATION SUITE                         ")
    print("================================================================================")
    all_passed = True

    # 1. Load data files
    try:
        assets_data = load_yaml(os.path.join(THREAT_MODEL_DIR, "assets.yaml"))
        actors_data = load_yaml(os.path.join(THREAT_MODEL_DIR, "actors.yaml"))
        tb_data = load_yaml(os.path.join(THREAT_MODEL_DIR, "trust-boundaries.yaml"))
        surfaces_data = load_yaml(os.path.join(THREAT_MODEL_DIR, "attack-surfaces.yaml"))
        threats_data = load_yaml(os.path.join(THREAT_MODEL_DIR, "threats.yaml"))
    except Exception as e:
        print(f"[-] FATAL: Error loading YAML data: {e}")
        return False

    # 2. Schema Validation
    schema_map = [
        (assets_data, os.path.join(SCHEMAS_DIR, "asset.schema.json"), "assets.yaml"),
        (actors_data, os.path.join(SCHEMAS_DIR, "actor.schema.json"), "actors.yaml"),
        (tb_data, os.path.join(SCHEMAS_DIR, "trust-boundary.schema.json"), "trust-boundaries.yaml"),
        (surfaces_data, os.path.join(SCHEMAS_DIR, "attack-surface.schema.json"), "attack-surfaces.yaml"),
        (threats_data, os.path.join(SCHEMAS_DIR, "threat.schema.json"), "threats.yaml"),
    ]

    for data, schema_path, name in schema_map:
        if not validate_schema(data, schema_path, name):
            all_passed = False

    if not all_passed:
        print("[-] Schema validation failed. Halting referential integrity checks.")
        return False

    # 3. Referential Integrity Checks
    print("\n[*] Validating Referential Integrity...")
    asset_ids = {a["id"] for a in assets_data.get("assets", [])}
    actor_ids = {a["id"] for a in actors_data.get("actors", [])}
    tb_ids = {tb["id"] for tb in tb_data.get("trust_boundaries", [])}
    surface_ids = {s["id"] for s in surfaces_data.get("attack_surfaces", [])}
    threat_ids = set()

    # Check component ownership in assets
    for asset in assets_data.get("assets", []):
        owner = asset.get("owner_component")
        if owner not in VALID_COMPONENTS:
            print(f"[-] Asset {asset['id']} references unknown component: {owner}")
            all_passed = False

    # Check trust boundaries in attack surfaces
    for surface in surfaces_data.get("attack_surfaces", []):
        tb = surface.get("trust_boundary")
        if tb not in tb_ids:
            print(f"[-] Attack surface {surface['id']} references unknown trust boundary: {tb}")
            all_passed = False
        comp = surface.get("target_component")
        if comp not in VALID_COMPONENTS:
            print(f"[-] Attack surface {surface['id']} references unknown component: {comp}")
            all_passed = False

    # Check threats references
    for threat in threats_data.get("threats", []):
        t_id = threat["id"]
        if t_id in threat_ids:
            print(f"[-] Duplicate Threat ID detected: {t_id}")
            all_passed = False
        threat_ids.add(t_id)

        # Assets
        for a_ref in threat.get("affected_assets", []):
            if a_ref not in asset_ids:
                print(f"[-] Threat {t_id} references non-existent asset: {a_ref}")
                all_passed = False

        # Actors
        for act_ref in threat.get("source_actors", []):
            if act_ref not in actor_ids:
                print(f"[-] Threat {t_id} references non-existent actor: {act_ref}")
                all_passed = False

        # Trust boundary
        tb_ref = threat.get("trust_boundary")
        if tb_ref not in tb_ids:
            print(f"[-] Threat {t_id} references non-existent trust boundary: {tb_ref}")
            all_passed = False

        # Attack surface
        as_ref = threat.get("attack_surface")
        if as_ref not in surface_ids:
            print(f"[-] Threat {t_id} references non-existent attack surface: {as_ref}")
            all_passed = False

        # Invariants
        for inv_ref in threat.get("invariants_threatened", []):
            if inv_ref not in VALID_INVARIANTS:
                print(f"[-] Threat {t_id} references non-existent invariant: {inv_ref}")
                all_passed = False

    # 4. Mandatory Threat Coverage Checks
    print("\n[*] Validating Mandatory Threat Coverage...")
    all_threat_titles_lower = " ".join([t["id"].lower() + " " + t["title"].lower() + " " + t["description"].lower() for t in threats_data.get("threats", [])])

    for trd_threat in MANDATORY_TRD_THREATS:
        words = trd_threat.split("_")
        if not all(w in all_threat_titles_lower for w in words):
            print(f"[-] Missing mandatory TRD Section 67 threat coverage: {trd_threat}")
            all_passed = False

    for add_threat in MANDATORY_ADDITIONAL_THREATS:
        words = add_threat.split("_")
        if not all(w in all_threat_titles_lower for w in words):
            print(f"[-] Missing mandatory additional threat coverage: {add_threat}")
            all_passed = False

    if all_passed:
        print("[+] All referential integrity and mandatory threat coverage checks PASSED!")
        print(f"[+] Total Assets: {len(asset_ids)}")
        print(f"[+] Total Actors: {len(actor_ids)}")
        print(f"[+] Total Trust Boundaries: {len(tb_ids)}")
        print(f"[+] Total Attack Surfaces: {len(surface_ids)}")
        print(f"[+] Total Registered Threats: {len(threat_ids)}")

        # 5. Baseline Manifest Integrity Verification
        manifest_path = os.path.join(BASE_DIR, "baseline.manifest")
        if os.path.exists(manifest_path):
            print("\n[*] Verifying Baseline Manifest Integrity...")
            with open(manifest_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            manifest_ok = True
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    expected_hash, rel_path = parts
                    abs_path = os.path.join(BASE_DIR, rel_path)
                    if os.path.exists(abs_path):
                        actual_hash = compute_file_sha256(abs_path)
                        if actual_hash != expected_hash:
                            print(f"[-] Hash mismatch for {rel_path}!")
                            print(f"    Expected: {expected_hash}")
                            print(f"    Actual:   {actual_hash}")
                            manifest_ok = False
                        else:
                            print(f"    [OK] {rel_path}")
                    else:
                        print(f"[-] Missing manifest file: {rel_path}")
                        manifest_ok = False
            if manifest_ok:
                print("[+] Baseline Manifest Integrity Verified!")
            else:
                print("[-] Baseline Manifest Verification Failed!")
                all_passed = False
        else:
            print(f"\n[!] Notice: {manifest_path} not found. Run manifest generation to seal baseline.")

    return all_passed

if __name__ == "__main__":
    success = run_validation()
    sys.exit(0 if success else 1)
