"""Deterministic release-gate policy for CI/CD container promotion."""
import re

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def release_gate(req):
    wf = req.get("workflow", {}) or {}
    image = req.get("image", {}) or {}
    perms = wf.get("permissions", {}) or {}
    violations = []

    if perms != {"contents": "read", "packages": "write", "id-token": "none"}:
        violations.append("EXCESS_PERMISSION")
    if wf.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    if wf.get("testsPassed") is not True or wf.get("matrixComplete") is not True or wf.get("failFast") is not False:
        violations.append("TESTS_INCOMPLETE")
    for a in wf.get("actions", []) or []:
        if a.get("owner") == "actions":
            continue
        if not SHA_RE.match(str(a.get("ref", ""))):
            violations.append("MUTABLE_ACTION")
            break
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")
    if req.get("target") == "production":
        if req.get("event") != "push" or req.get("ref") != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if wf.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {"decision": "promote" if not violations else "block", "violations": violations}
