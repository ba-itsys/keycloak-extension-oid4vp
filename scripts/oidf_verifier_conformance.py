#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import http.cookiejar
import http.server
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


PID_LOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
REQUEST_TIMEOUT = 60
POLL_INTERVAL_SECONDS = 2
WAITING_TIMEOUT_SECONDS = 60
RUN_TIMEOUT_SECONDS = 15 * 60
REALM = "wallet-demo"
WALLET_CLIENT_ID = "wallet-mock"
MDL_ISSUER_CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIICqTCCAlCgAwIBAgIUEmctHgzxSGqk6Z8Eb+0s97VZdpowCgYIKoZIzj0EAwIw
gYcxCzAJBgNVBAYTAlVTMRgwFgYDVQQIDA9TdGF0ZSBvZiBVdG9waWExEjAQBgNV
BAcMCVNhbiBSYW1vbjEaMBgGA1UECgwRT3BlbklEIEZvdW5kYXRpb24xCzAJBgNV
BAsMAklUMSEwHwYDVQQDDBhjZXJ0aWZpY2F0aW9uLm9wZW5pZC5uZXQwHhcNMjUw
NzMwMDc0NzIyWhcNMjYwNzMwMDc0NzIyWjCBhzELMAkGA1UEBhMCVVMxGDAWBgNV
BAgMD1N0YXRlIG9mIFV0b3BpYTESMBAGA1UEBwwJU2FuIFJhbW9uMRowGAYDVQQK
DBFPcGVuSUQgRm91bmRhdGlvbjELMAkGA1UECwwCSVQxITAfBgNVBAMMGGNlcnRp
ZmljYXRpb24ub3BlbmlkLm5ldDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ5o
lgDBiHqNhN7rFkSy/xD34dQcOSR4KvEWMyb62jI+UGUofeAi/55RIt74pBsQz9+B
48WXI8xhIphoNN7AejajgZcwgZQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
Af8EBAMCAQYwIQYDVR0SBBowGIEWY2VydGlmaWNhdGlvbkBvaWRmLm9yZzAsBgNV
HR8EJTAjMCGgH6AdhhtodHRwOi8vZXhhbXBsZS5jb20vbXljYS5jcmwwHQYDVR0O
BBYEFHhk9LVVH8Gt9ZgfxgyhSl921XOhMAoGCCqGSM49BAMCA0cAMEQCICBxjCq9
efAwMKREK+k0OXBtiQCbFD7QdpyH42LVYfdvAiAurlZwp9PtmQZzoSYDUvXpZM5v
TvFLVc4ESGy3AtdC+g==
-----END CERTIFICATE-----
"""


@dataclass(frozen=True)
class CredentialProfile:
    slug: str
    user_mapping_claim: str
    user_mapping_claim_mdoc: str
    mappers: list[dict[str, object]]
    dcql_query: dict[str, object]
    include_mdl_issuer: bool = False


SD_JWT_PROFILE = CredentialProfile(
    slug="sd_jwt_vc",
    user_mapping_claim="given_name",
    user_mapping_claim_mdoc="given_name",
    mappers=[
        {
            "name": "sd-jwt-given_name",
            "identityProviderMapper": "oid4vp-user-attribute-mapper",
            "config": {
                "syncMode": "INHERIT",
                "credential.format": "dc+sd-jwt",
                "credential.type": "pid",
                "claim": "given_name",
                "user.attribute": "firstName",
            },
        },
        {
            "name": "sd-jwt-family_name",
            "identityProviderMapper": "oid4vp-user-attribute-mapper",
            "config": {
                "syncMode": "INHERIT",
                "credential.format": "dc+sd-jwt",
                "credential.type": "pid",
                "claim": "family_name",
                "user.attribute": "lastName",
            },
        },
    ],
    dcql_query={
        "credentials": [
            {
                "id": "pid_sd_jwt",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}],
            }
        ],
        "credential_sets": [{"options": [["pid_sd_jwt"]], "required": True}],
    },
)

ISO_MDL_PROFILE = CredentialProfile(
    slug="iso_mdl",
    user_mapping_claim="given_name",
    user_mapping_claim_mdoc="org.iso.18013.5.1/given_name",
    mappers=[
        {
            "name": "mdoc-given_name",
            "identityProviderMapper": "oid4vp-user-attribute-mapper",
            "config": {
                "syncMode": "INHERIT",
                "credential.format": "mso_mdoc",
                "credential.type": "org.iso.18013.5.1.mDL",
                "claim": "org.iso.18013.5.1/given_name",
                "user.attribute": "firstName",
            },
        },
        {
            "name": "mdoc-family_name",
            "identityProviderMapper": "oid4vp-user-attribute-mapper",
            "config": {
                "syncMode": "INHERIT",
                "credential.format": "mso_mdoc",
                "credential.type": "org.iso.18013.5.1.mDL",
                "claim": "org.iso.18013.5.1/family_name",
                "user.attribute": "lastName",
            },
        },
    ],
    dcql_query={
        "credentials": [
            {
                "id": "pid_mdoc",
                "format": "mso_mdoc",
                "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                "claims": [
                    {"path": ["org.iso.18013.5.1", "given_name"]},
                    {"path": ["org.iso.18013.5.1", "family_name"]},
                ],
            }
        ],
        "credential_sets": [{"options": [["pid_mdoc"]], "required": True}],
    },
    include_mdl_issuer=True,
)


@dataclass(frozen=True)
class Scenario:
    slug: str
    label: str
    plan_name: str
    variant: dict[str, str]
    credential_profile: CredentialProfile
    client_id_scheme: str
    response_mode: str
    enforce_haip: bool


SCENARIOS = [
    Scenario(
        slug="vp-final-sdjwt-x509-san-dns-direct-post-jwt",
        label="OID4VP Final verifier: SD-JWT VC, x509_san_dns, direct_post.jwt",
        plan_name="oid4vp-1final-verifier-test-plan",
        variant={
            "vp_profile": "plain_vp",
            "credential_format": "sd_jwt_vc",
            "client_id_prefix": "x509_san_dns",
            "request_method": "request_uri_signed",
            "response_mode": "direct_post.jwt",
        },
        credential_profile=SD_JWT_PROFILE,
        client_id_scheme="x509_san_dns",
        response_mode="direct_post.jwt",
        enforce_haip=False,
    ),
    Scenario(
        slug="vp-final-sdjwt-x509-hash-direct-post-jwt",
        label="OID4VP Final verifier: SD-JWT VC, x509_hash, direct_post.jwt",
        plan_name="oid4vp-1final-verifier-test-plan",
        variant={
            "vp_profile": "plain_vp",
            "credential_format": "sd_jwt_vc",
            "client_id_prefix": "x509_hash",
            "request_method": "request_uri_signed",
            "response_mode": "direct_post.jwt",
        },
        credential_profile=SD_JWT_PROFILE,
        client_id_scheme="x509_hash",
        response_mode="direct_post.jwt",
        enforce_haip=False,
    ),
    Scenario(
        slug="vp-final-mdoc-x509-san-dns-direct-post-jwt",
        label="OID4VP Final verifier: ISO mDL, x509_san_dns, direct_post.jwt",
        plan_name="oid4vp-1final-verifier-test-plan",
        variant={
            "vp_profile": "plain_vp",
            "credential_format": "iso_mdl",
            "client_id_prefix": "x509_san_dns",
            "request_method": "request_uri_signed",
            "response_mode": "direct_post.jwt",
        },
        credential_profile=ISO_MDL_PROFILE,
        client_id_scheme="x509_san_dns",
        response_mode="direct_post.jwt",
        enforce_haip=False,
    ),
    Scenario(
        slug="vp-final-mdoc-x509-hash-direct-post-jwt",
        label="OID4VP Final verifier: ISO mDL, x509_hash, direct_post.jwt",
        plan_name="oid4vp-1final-verifier-test-plan",
        variant={
            "vp_profile": "plain_vp",
            "credential_format": "iso_mdl",
            "client_id_prefix": "x509_hash",
            "request_method": "request_uri_signed",
            "response_mode": "direct_post.jwt",
        },
        credential_profile=ISO_MDL_PROFILE,
        client_id_scheme="x509_hash",
        response_mode="direct_post.jwt",
        enforce_haip=False,
    ),
    Scenario(
        slug="vp-haip-sdjwt-direct-post-jwt",
        label="OID4VP Final/HAIP verifier: SD-JWT VC, x509_hash, direct_post.jwt",
        plan_name="oid4vp-1final-verifier-haip-test-plan",
        variant={
            "credential_format": "sd_jwt_vc",
            "response_mode": "direct_post.jwt",
        },
        credential_profile=SD_JWT_PROFILE,
        client_id_scheme="x509_hash",
        response_mode="direct_post.jwt",
        enforce_haip=True,
    ),
    Scenario(
        slug="vp-haip-mdoc-direct-post-jwt",
        label="OID4VP Final/HAIP verifier: ISO mDL, x509_hash, direct_post.jwt",
        plan_name="oid4vp-1final-verifier-haip-test-plan",
        variant={
            "credential_format": "iso_mdl",
            "response_mode": "direct_post.jwt",
        },
        credential_profile=ISO_MDL_PROFILE,
        client_id_scheme="x509_hash",
        response_mode="direct_post.jwt",
        enforce_haip=True,
    ),
]


class JsonHttpError(RuntimeError):
    pass


class AdminClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self._token = self._request_token()

    def get_json(self, path: str):
        return self._request_json("GET", path)

    def get_json_list(self, path: str):
        return self._request_json("GET", path)

    def post_json(self, path: str, payload: object):
        self._request_json("POST", path, payload)

    def put_json(self, path: str, payload: object):
        self._request_json("PUT", path, payload)

    def delete_if_exists(self, path: str) -> bool:
        try:
            self._request_json("DELETE", path)
            return True
        except JsonHttpError as exc:
            if "HTTP 404" in str(exc):
                return False
            raise

    def _request_token(self) -> str:
        form = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.username,
                "password": self.password,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + "/realms/master/protocol/openid-connect/token",
            data=form,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-Proto": "https"},
        )
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))["access_token"]

    def _request_json(self, method: str, path: str, payload: object | None = None):
        url = self.base_url + (path if path.startswith("/") else "/" + path)
        headers = {"Authorization": f"Bearer {self._token}", "X-Forwarded-Proto": "https"}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                self._token = self._request_token()
                return self._request_json(method, path, payload)
            body = exc.read().decode("utf-8", errors="replace")
            raise JsonHttpError(f"{method} {url} -> HTTP {exc.code}: {body}") from exc


class ConformanceClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def create_plan(self, plan_name: str, variant: dict[str, str], config: dict[str, object]) -> dict[str, object]:
        query = urllib.parse.urlencode(
            {"planName": plan_name, "variant": json.dumps(variant, separators=(",", ":"))}
        )
        return self._request_json("POST", f"/api/plan?{query}", config)

    def load_plan(self, plan_id: str) -> dict[str, object]:
        return self._request_json("GET", f"/api/plan/{urllib.parse.quote(plan_id)}")

    def start_module(self, plan_id: str, module_name: str) -> dict[str, object]:
        query = urllib.parse.urlencode({"test": module_name, "plan": plan_id})
        return self._request_json("POST", f"/api/runner?{query}", "")

    def load_run_info(self, run_id: str) -> dict[str, object]:
        return self._request_json("GET", f"/api/info/{urllib.parse.quote(run_id)}")

    def load_run_log(self, run_id: str) -> list[dict[str, object]]:
        return self._request_json("GET", f"/api/log/{urllib.parse.quote(run_id)}")

    def delete_plan(self, plan_id: str) -> None:
        self._request_json("DELETE", f"/api/plan/{urllib.parse.quote(plan_id)}")

    def _request_json(self, method: str, path: str, payload: object | None = None):
        url = self.base_url + path
        headers = {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            if isinstance(payload, str):
                data = payload.encode("utf-8")
            else:
                data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise JsonHttpError(f"{method} {url} -> HTTP {exc.code}: {body}") from exc


class QuietRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args) -> None:
        return


class TrustListServer:
    def __init__(self, root: Path):
        self.root = root
        handler = lambda *args, **kwargs: QuietRequestHandler(*args, directory=str(root), **kwargs)
        self.httpd = socketserver.ThreadingTCPServer(("0.0.0.0", 0), handler)
        self.httpd.allow_reuse_address = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


@dataclass(frozen=True)
class SigningMaterial:
    combined_pem: str
    leaf_cert_pem: str
    ca_cert_pem: str
    leaf_cert_der: bytes
    jwk: dict[str, str]
    x509_hash: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the OIDF OID4VP Final verifier plans and the HAIP verifier plan against local Keycloak"
    )
    parser.add_argument("--work-dir", required=True, help="Directory for temporary files and reports")
    parser.add_argument("--local-base-url", required=True, help="Local Keycloak base URL")
    parser.add_argument("--public-base-url", required=True, help="Public HTTPS Keycloak base URL")
    parser.add_argument("--report-json", required=True, help="Path for the JSON report")
    parser.add_argument(
        "--delete-passing-plans",
        action="store_true",
        help="Delete successful OIDF plans after the run",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="Run only the named scenario slug; may be passed more than once",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    suite_base_url = os.environ.get("OID4VP_CONFORMANCE_BASE_URL") or os.environ.get("OIDF_CONFORMANCE_BASE_URL")
    if not suite_base_url:
        suite_base_url = "https://demo.certification.openid.net"
    api_key = os.environ.get("OID4VP_CONFORMANCE_API_KEY") or os.environ.get("OIDF_CONFORMANCE_API_KEY")
    if not api_key:
        print("error: missing OID4VP_CONFORMANCE_API_KEY or OIDF_CONFORMANCE_API_KEY", file=sys.stderr)
        return 1

    work_dir = Path(args.work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(args.report_json).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)

    selected = [scenario for scenario in SCENARIOS if not args.scenario or scenario.slug in set(args.scenario)]
    if not selected:
        print("error: no matching scenarios selected", file=sys.stderr)
        return 1

    admin = AdminClient(args.local_base_url, "admin", "admin")
    conformance = ConformanceClient(suite_base_url, api_key)

    public_host = urllib.parse.urlsplit(args.public_base_url).hostname
    if not public_host:
        print("error: failed to resolve host from public base URL", file=sys.stderr)
        return 1

    signing_material = generate_signing_material(work_dir, public_host)
    trust_list_root = work_dir / "trustlist"
    trust_list_root.mkdir(parents=True, exist_ok=True)
    trust_list_server = TrustListServer(trust_list_root)
    trust_list_server.start()
    trust_list_url = f"http://host.docker.internal:{trust_list_server.port}/trustlist.jwt"

    results: dict[str, object] = {
        "suite_base_url": suite_base_url,
        "public_base_url": args.public_base_url,
        "local_base_url": args.local_base_url,
        "delete_passing_plans": args.delete_passing_plans,
        "scenarios": [],
    }

    base_idp = admin.get_json(f"/admin/realms/{REALM}/identity-provider/instances/oid4vp")

    try:
        for scenario in selected:
            try:
                scenario_result = run_scenario(
                    admin=admin,
                    conformance=conformance,
                    base_idp=base_idp,
                    signing_material=signing_material,
                    trust_list_root=trust_list_root,
                    trust_list_url=trust_list_url,
                    public_base_url=args.public_base_url,
                    scenario=scenario,
                    delete_passing_plans=args.delete_passing_plans,
                )
            except Exception as exc:
                scenario_result = {
                    "slug": scenario.slug,
                    "label": scenario.label,
                    "plan_name": scenario.plan_name,
                    "plan_id": None,
                    "plan_url": None,
                    "passed": False,
                    "deleted": False,
                    "modules": [],
                    "error": str(exc),
                }
            results["scenarios"].append(scenario_result)
    finally:
        trust_list_server.close()

    report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print_human_report(results, report_path)
    return 0 if all(entry["passed"] for entry in results["scenarios"]) else 1


def run_scenario(
    *,
    admin: AdminClient,
    conformance: ConformanceClient,
    base_idp: dict[str, object],
    signing_material: SigningMaterial,
    trust_list_root: Path,
    trust_list_url: str,
    public_base_url: str,
    scenario: Scenario,
    delete_passing_plans: bool,
) -> dict[str, object]:
    alias = "oid4vp-conf-" + uuid.uuid4().hex
    plan_id = None
    modules_result: list[dict[str, object]] = []

    trust_list_filename = f"trustlist-{alias}.jwt"
    scenario_trust_list_url = derive_trust_list_url(trust_list_url, trust_list_filename)
    trusted_certs = [signing_material.leaf_cert_pem, signing_material.ca_cert_pem]
    if scenario.credential_profile.include_mdl_issuer:
        trusted_certs.append(MDL_ISSUER_CERTIFICATE_PEM)
    trust_list_root.joinpath(trust_list_filename).write_text(
        build_unsigned_trust_list_jwt(trusted_certs), encoding="utf-8"
    )

    configure_identity_provider(
        admin=admin,
        base_idp=base_idp,
        alias=alias,
        trust_list_url=scenario_trust_list_url,
        signing_material=signing_material,
        scenario=scenario,
    )

    passed = False
    delete_plan = delete_passing_plans
    try:
        plan = conformance.create_plan(
            scenario.plan_name,
            scenario.variant,
            build_plan_config(scenario, signing_material, public_base_url),
        )
        plan_id = first_non_blank(plan.get("id"), plan.get("_id"))
        if not plan_id:
            raise RuntimeError(f"{scenario.slug}: OIDF suite did not return a plan id")

        plan_info = conformance.load_plan(plan_id)
        modules = [
            first_non_blank(module.get("testModule"), module.get("name"))
            for module in plan_info.get("modules", [])
            if first_non_blank(module.get("testModule"), module.get("name"))
        ]
        if not modules:
            raise RuntimeError(f"{scenario.slug}: conformance plan returned no modules")

        for module_name in modules:
            module_result = run_module(
                conformance=conformance,
                public_base_url=public_base_url,
                alias=alias,
                scenario=scenario,
                signing_material=signing_material,
                plan_id=plan_id,
                module_name=module_name,
            )
            modules_result.append(module_result)
            if not module_result["passed"]:
                delete_plan = False
        passed = all(module["passed"] for module in modules_result)
    except Exception:
        delete_plan = False
        raise
    finally:
        admin.delete_if_exists(f"/admin/realms/{REALM}/identity-provider/instances/{alias}")
        if plan_id and delete_plan and passed:
            conformance.delete_plan(plan_id)

    return {
        "slug": scenario.slug,
        "label": scenario.label,
        "plan_name": scenario.plan_name,
        "plan_id": plan_id,
        "plan_url": f"{conformance.base_url}/plan-detail.html?plan={plan_id}" if plan_id else None,
        "passed": passed,
        "deleted": bool(plan_id and delete_plan and passed),
        "modules": modules_result,
    }


def configure_identity_provider(
    *,
    admin: AdminClient,
    base_idp: dict[str, object],
    alias: str,
    trust_list_url: str,
    signing_material: SigningMaterial,
    scenario: Scenario,
) -> None:
    idp = copy.deepcopy(base_idp)
    idp.pop("internalId", None)
    idp.pop("types", None)
    idp["alias"] = alias
    idp["displayName"] = "Sign in with Wallet"
    idp["providerId"] = "oid4vp"
    config = dict(idp.get("config", {}))
    config["clientId"] = "not-used"
    config["clientSecret"] = "not-used"
    config["clientIdScheme"] = scenario.client_id_scheme
    config["responseMode"] = scenario.response_mode
    config["enforceHaip"] = str(scenario.enforce_haip).lower()
    config["sameDeviceEnabled"] = "true"
    config["crossDeviceEnabled"] = "false"
    config["trustedAuthoritiesMode"] = "none"
    config["statusListMaxCacheTtlSeconds"] = "0"
    config["trustListUrl"] = trust_list_url
    config["trustListLoTEType"] = PID_LOTE_TYPE
    config["x509CertificatePem"] = signing_material.combined_pem
    config["userMappingClaim"] = scenario.credential_profile.user_mapping_claim
    config["userMappingClaimMdoc"] = scenario.credential_profile.user_mapping_claim_mdoc
    config["dcqlQuery"] = json.dumps(scenario.credential_profile.dcql_query)
    config.pop("verifierInfo", None)
    idp["config"] = config

    admin.delete_if_exists(f"/admin/realms/{REALM}/identity-provider/instances/{alias}")
    admin.post_json(f"/admin/realms/{REALM}/identity-provider/instances", idp)
    replace_identity_provider_mappers(admin, alias, scenario.credential_profile.mappers)


def replace_identity_provider_mappers(admin: AdminClient, alias: str, mappers: list[dict[str, object]]) -> None:
    base_path = f"/admin/realms/{REALM}/identity-provider/instances/{alias}/mappers"
    for mapper in admin.get_json_list(base_path):
        mapper_id = mapper.get("id")
        if mapper_id:
            admin.delete_if_exists(f"{base_path}/{mapper_id}")
    for mapper in mappers:
        payload = {
            "name": mapper["name"],
            "identityProviderAlias": alias,
            "identityProviderMapper": mapper["identityProviderMapper"],
            "config": mapper["config"],
        }
    admin.post_json(base_path, payload)


def derive_trust_list_url(base_url: str, filename: str) -> str:
    parts = urllib.parse.urlsplit(base_url)
    path = parts.path or "/"
    if "/" in path:
        directory = path.rsplit("/", 1)[0]
    else:
        directory = ""
    new_path = f"{directory}/{filename}" if directory else f"/{filename}"
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, new_path, "", ""))


def build_plan_config(scenario: Scenario, signing_material: SigningMaterial, public_base_url: str) -> dict[str, object]:
    public_host = urllib.parse.urlsplit(public_base_url).hostname or ""
    client_id = public_host if scenario.client_id_scheme == "x509_san_dns" else signing_material.x509_hash
    signing_jwk = dict(signing_material.jwk)
    signing_jwk["x5c"] = [base64.b64encode(signing_material.leaf_cert_der).decode("ascii")]
    return {
        "alias": "keycloak-oid4vp-" + uuid.uuid4().hex,
        "description": f"Keycloak verifier conformance: {scenario.label}",
        "publish": "private",
        "client": {"client_id": client_id},
        "credential": {"signing_jwk": signing_jwk},
    }


def run_module(
    *,
    conformance: ConformanceClient,
    public_base_url: str,
    alias: str,
    scenario: Scenario,
    signing_material: SigningMaterial,
    plan_id: str,
    module_name: str,
) -> dict[str, object]:
    start = conformance.start_module(plan_id, module_name)
    run_id = first_non_blank(start.get("id"), start.get("_id"))
    if not run_id:
        raise RuntimeError(f"{scenario.slug}/{module_name}: conformance suite did not return a run id")

    await_waiting_state(conformance, run_id)
    info = conformance.load_run_info(run_id)
    authorization_endpoint = resolve_authorization_endpoint(start, info)
    assert_local_authorization_request_matches_scenario(public_base_url, alias, scenario, signing_material)
    trigger_same_device_flow(public_base_url, alias, authorization_endpoint)
    result = await_run_completion(conformance, run_id)
    log_lines = normalize_log(conformance.load_run_log(run_id))
    passed = is_passed(result.get("status"), result.get("result"))

    return {
        "module": module_name,
        "run_id": run_id,
        "run_url": first_non_blank(start.get("url"), start.get("testUrl")),
        "status": result.get("status"),
        "result": result.get("result"),
        "passed": passed,
        "log_url": f"{conformance.base_url}/log-detail.html?log={run_id}",
        "log": log_lines,
    }


def await_waiting_state(conformance: ConformanceClient, run_id: str) -> None:
    deadline = time.time() + WAITING_TIMEOUT_SECONDS
    last_status = None
    while time.time() < deadline:
        info = conformance.load_run_info(run_id)
        last_status = info.get("status")
        if str(last_status).upper() == "WAITING":
            return
        if is_terminal(last_status):
            raise RuntimeError(f"run {run_id} entered terminal state before verifier call: {last_status}")
        time.sleep(0.25)
    raise RuntimeError(f"run {run_id} did not reach WAITING in time; last status={last_status}")


def await_run_completion(conformance: ConformanceClient, run_id: str) -> dict[str, object]:
    deadline = time.time() + RUN_TIMEOUT_SECONDS
    last_info = {}
    while time.time() < deadline:
        last_info = conformance.load_run_info(run_id)
        if is_terminal(last_info.get("status")):
            return last_info
        time.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"run {run_id} did not finish in time; last status={last_info.get('status')}")


def resolve_authorization_endpoint(start: dict[str, object], info: dict[str, object]) -> str:
    exported = info.get("exported") or {}
    authorization_endpoint = exported.get("authorization_endpoint")
    if authorization_endpoint:
        return authorization_endpoint
    run_url = first_non_blank(start.get("url"), start.get("testUrl"))
    if run_url:
        return run_url.rstrip("/") + "/authorize" if "/authorize" not in run_url else run_url
    raise RuntimeError("OIDF run info did not expose authorization_endpoint")


def trigger_same_device_flow(public_base_url: str, alias: str, authorization_endpoint: str) -> None:
    local_request = fetch_same_device_authorization_request(public_base_url, alias)
    query = urllib.parse.urlencode(
        {"client_id": local_request["client_id"], "request_uri": local_request["request_uri"]}
    )
    url = authorization_endpoint + ("&" if "?" in authorization_endpoint else "?") + query
    opener = local_request["opener"]
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/html,application/json",
            "ngrok-skip-browser-warning": "true",
        },
    )
    with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
        if not 200 <= response.status < 400:
            body = response.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"unexpected suite authorization response {response.status}: {body}")


def assert_local_authorization_request_matches_scenario(
    public_base_url: str,
    alias: str,
    scenario: Scenario,
    signing_material: SigningMaterial,
) -> None:
    local_request = fetch_same_device_authorization_request(public_base_url, alias)
    public_host = urllib.parse.urlsplit(public_base_url).hostname or ""
    raw_client_id = public_host if scenario.client_id_scheme == "x509_san_dns" else signing_material.x509_hash
    expected_client_id = (
        f"x509_san_dns:{raw_client_id}" if scenario.client_id_scheme == "x509_san_dns" else f"x509_hash:{raw_client_id}"
    )
    actual_client_id = local_request["client_id"]
    claims_client_id = local_request["claims"].get("client_id")
    if actual_client_id != expected_client_id:
        raise RuntimeError(
            f"{scenario.slug}: unexpected wallet client_id {actual_client_id!r}, expected {expected_client_id!r}"
        )
    if claims_client_id != expected_client_id:
        raise RuntimeError(
            f"{scenario.slug}: unexpected request object client_id {claims_client_id!r}, expected {expected_client_id!r}"
        )
    dcql_query = local_request["claims"].get("dcql_query")
    credentials = dcql_query.get("credentials") if isinstance(dcql_query, dict) else None
    if not isinstance(credentials, list) or len(credentials) != 1:
        raise RuntimeError(f"{scenario.slug}: request object did not contain exactly one DCQL credential")


def fetch_same_device_authorization_request(public_base_url: str, alias: str) -> dict[str, object]:
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    code_verifier = uuid.uuid4().hex + uuid.uuid4().hex
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode(
        "ascii"
    )
    login_url = (
        f"{public_base_url}/realms/{REALM}/protocol/openid-connect/auth?"
        + urllib.parse.urlencode(
            {
                "client_id": WALLET_CLIENT_ID,
                "response_type": "code",
                "scope": "openid",
                "redirect_uri": public_base_url + "/callback",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "kc_idp_hint": alias,
            }
        )
    )
    request = urllib.request.Request(
        login_url,
        headers={"Accept": "text/html", "ngrok-skip-browser-warning": "true"},
    )
    with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
        html = response.read().decode("utf-8")
    wallet_url = extract_same_device_wallet_url(html)
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(wallet_url).query)
    client_id = require_single_query_value(params, "client_id")
    request_uri = require_single_query_value(params, "request_uri")
    request_obj = urllib.request.Request(
        request_uri,
        headers={
            "Accept": "application/oauth-authz-req+jwt,application/jwt,text/plain",
            "ngrok-skip-browser-warning": "true",
        },
    )
    with opener.open(request_obj, timeout=REQUEST_TIMEOUT) as response:
        body = response.read().decode("utf-8")
    claims = parse_compact_jwt_claims(body)
    return {"opener": opener, "client_id": client_id, "request_uri": request_uri, "claims": claims}


def extract_same_device_wallet_url(login_html: str) -> str:
    marker = login_html.find('id="oid4vp-open-wallet"')
    if marker < 0:
        raise RuntimeError("OID4VP login page did not contain the same-device wallet action")
    href_marker = login_html.find('href="', marker)
    if href_marker < 0:
        raise RuntimeError("OID4VP login page did not contain a same-device href")
    start = href_marker + len('href="')
    end = login_html.find('"', start)
    if end < 0:
        raise RuntimeError("OID4VP login page contained an unterminated same-device href")
    return login_html[start:end].replace("&amp;", "&")


def require_single_query_value(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key) or []
    if len(values) != 1 or not values[0]:
        raise RuntimeError(f"expected exactly one {key} value in authorization request")
    return values[0]


def parse_compact_jwt_claims(compact_jwt: str) -> dict[str, object]:
    parts = compact_jwt.split(".")
    if len(parts) != 3:
        raise RuntimeError("expected compact JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))


def is_terminal(status: object) -> bool:
    normalized = str(status or "").upper()
    return normalized in {"FINISHED", "INTERRUPTED"}


def is_passed(status: object, result: object) -> bool:
    normalized_status = str(status or "").upper()
    normalized_result = str(result or "").upper()
    return normalized_status == "FINISHED" and normalized_result in {"PASSED", "SUCCESS", "WARNING", "SKIPPED"}


def normalize_log(entries: list[dict[str, object]]) -> list[str]:
    lines = []
    for entry in entries or []:
        prefix = str(entry.get("result") or "").strip()
        message = str(entry.get("msg") or "").strip()
        line = " ".join(part for part in [prefix, message] if part)
        if line:
            lines.append(line)
    return lines


def build_unsigned_trust_list_jwt(certificates_pem: list[str]) -> str:
    x509_entries = []
    for certificate_pem in certificates_pem:
        certificate_body = "".join(
            line.strip()
            for line in certificate_pem.splitlines()
            if line and "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
        )
        x509_entries.append({"val": certificate_body})
    payload = {
        "LoTE": {
            "ListAndSchemeInformation": {
                "LoTEType": PID_LOTE_TYPE,
                "NextUpdate": (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat(),
            },
            "TrustedEntitiesList": [
                {
                    "TrustedEntityServices": [
                        {
                            "ServiceInformation": {
                                "ServiceTypeIdentifier": PID_LOTE_TYPE + "/Issuance",
                                "ServiceDigitalIdentity": {"X509Certificates": x509_entries},
                            }
                        }
                    ]
                }
            ],
        }
    }
    header = {"alg": "none", "typ": "JWT"}
    return ".".join(
        [
            b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
            "",
        ]
    )


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_signing_material(work_dir: Path, public_host: str) -> SigningMaterial:
    cert_dir = work_dir / "verifier-material"
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key = cert_dir / "ca.key.pem"
    ca_cert = cert_dir / "ca.cert.pem"
    leaf_key = cert_dir / "leaf.key.pem"
    leaf_key_pk8 = cert_dir / "leaf.key.pk8.pem"
    leaf_csr = cert_dir / "leaf.csr.pem"
    leaf_cert = cert_dir / "leaf.cert.pem"
    leaf_conf = cert_dir / "leaf.cnf"
    cert_ext = cert_dir / "leaf.ext"

    leaf_conf.write_text(
        f"""[req]
distinguished_name = dn
prompt = no
req_extensions = req_ext

[dn]
CN = {public_host}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = {public_host}
""",
        encoding="utf-8",
    )
    cert_ext.write_text(
        f"""basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:{public_host}
""",
        encoding="utf-8",
    )

    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)])
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-key",
            str(ca_key),
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=OIDF Verifier Test CA",
            "-out",
            str(ca_cert),
        ]
    )
    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(leaf_key)])
    run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            str(leaf_key),
            "-config",
            str(leaf_conf),
            "-out",
            str(leaf_csr),
        ]
    )
    run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(leaf_csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "2",
            "-sha256",
            "-extfile",
            str(cert_ext),
            "-out",
            str(leaf_cert),
        ]
    )
    run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(leaf_key), "-out", str(leaf_key_pk8)])

    leaf_cert_pem = leaf_cert.read_text(encoding="utf-8").strip()
    ca_cert_pem = ca_cert.read_text(encoding="utf-8").strip()
    leaf_key_pem = leaf_key_pk8.read_text(encoding="utf-8").strip()
    combined_pem = leaf_cert_pem + "\n" + ca_cert_pem + "\n" + leaf_key_pem + "\n"
    leaf_cert_der = pem_to_der(leaf_cert_pem)
    jwk = extract_ec_jwk(leaf_key_pk8)
    jwk["kid"] = uuid.uuid4().hex
    jwk["alg"] = "ES256"
    x509_hash = b64url(hashlib.sha256(leaf_cert_der).digest())
    return SigningMaterial(
        combined_pem=combined_pem,
        leaf_cert_pem=leaf_cert_pem,
        ca_cert_pem=ca_cert_pem,
        leaf_cert_der=leaf_cert_der,
        jwk=jwk,
        x509_hash=x509_hash,
    )


def run(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def pem_to_der(pem_text: str) -> bytes:
    body = "".join(
        line.strip()
        for line in pem_text.splitlines()
        if line and "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
    )
    return base64.b64decode(body.encode("ascii"))


def extract_ec_jwk(private_key_path: Path) -> dict[str, str]:
    result = subprocess.run(
        ["openssl", "pkey", "-in", str(private_key_path), "-text", "-noout"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    output = result.stdout
    priv_match = re.search(r"priv:\n((?:\s+[0-9a-f:]+\n)+)", output, re.IGNORECASE)
    pub_match = re.search(r"pub:\n((?:\s+[0-9a-f:]+\n)+)", output, re.IGNORECASE)
    if not priv_match or not pub_match:
        raise RuntimeError("failed to parse openssl EC key output")
    private_hex = strip_hex_block(priv_match.group(1))
    public_hex = strip_hex_block(pub_match.group(1))
    if public_hex.startswith("04"):
        public_hex = public_hex[2:]
    if len(public_hex) != 128:
        raise RuntimeError("unexpected EC public key length")
    x_hex = public_hex[:64]
    y_hex = public_hex[64:]
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(bytes.fromhex(x_hex)),
        "y": b64url(bytes.fromhex(y_hex)),
        "d": b64url(bytes.fromhex(private_hex.zfill(64))),
    }


def strip_hex_block(value: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", value)


def first_non_blank(*values: object) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def print_human_report(report: dict[str, object], report_path: Path) -> None:
    overall_passed = all(entry["passed"] for entry in report["scenarios"])
    print("")
    for scenario in report["scenarios"]:
        status = "PASSED" if scenario["passed"] else "FAILED"
        print(f"{status}  {scenario['label']}")
        print(f"  plan: {scenario['plan_url']}")
        if scenario.get("error"):
            print(f"  error: {scenario['error']}")
        for module in scenario["modules"]:
            module_status = "PASS" if module["passed"] else "FAIL"
            print(f"  {module_status:<4} {module['module']} [{module['status']}/{module['result']}]")
            if not module["passed"]:
                print(f"       log: {module['log_url']}")
    print("")
    print(f"Overall: {'PASSED' if overall_passed else 'FAILED'}")
    print(f"Report:  {report_path}")


if __name__ == "__main__":
    raise SystemExit(main())
