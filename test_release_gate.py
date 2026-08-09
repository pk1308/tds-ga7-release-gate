from release_gate import release_gate

BASE = {
    "target": "preview", "event": "pull_request", "ref": "refs/heads/dev",
    "workflow": {"trigger": "pull_request",
                 "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
                 "testsPassed": True, "matrixComplete": True, "failFast": False,
                 "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}]},
    "image": {"multiStage": True, "runsAsRoot": False, "secretMode": "none",
              "criticalVulnerabilities": 0, "digestPinned": True},
}


def test_clean_promote():
    assert release_gate(dict(BASE)) == {"decision": "promote", "violations": []}


def test_excess_permission():
    r = dict(BASE); r["workflow"] = {**r["workflow"], "permissions": {"contents": "read", "packages": "write", "id-token": "write"}}
    assert "EXCESS_PERMISSION" in release_gate(r)["violations"]


def test_unsafe_trigger():
    r = dict(BASE); r["workflow"] = {**r["workflow"], "trigger": "pull_request_target"}
    assert "UNSAFE_PR_TRIGGER" in release_gate(r)["violations"]


def test_mutable_action():
    r = dict(BASE); r["workflow"] = {**r["workflow"], "actions": [{"owner": "acme", "name": "x", "ref": "v3"}]}
    assert "MUTABLE_ACTION" in release_gate(r)["violations"]


def test_production_clean():
    r = dict(BASE, target="production", event="push", ref="refs/heads/main")
    r["workflow"] = {**r["workflow"], "environmentApproval": True}
    assert release_gate(r)["decision"] == "promote"


def test_production_bad_ref():
    r = dict(BASE, target="production", event="push", ref="refs/heads/main")
    r["workflow"] = {**r["workflow"], "environmentApproval": True}
    r["ref"] = "refs/heads/dev"
    assert "INVALID_PRODUCTION_REF" in release_gate(r)["violations"]


def test_image_faults():
    for over, code in [({"image": {**BASE["image"], "runsAsRoot": True}}, "ROOT_RUNTIME"),
                       ({"image": {**BASE["image"], "multiStage": False}}, "SINGLE_STAGE_IMAGE"),
                       ({"image": {**BASE["image"], "digestPinned": False}}, "UNPINNED_IMAGE")]:
        assert code in release_gate({**BASE, **over})["violations"], code
