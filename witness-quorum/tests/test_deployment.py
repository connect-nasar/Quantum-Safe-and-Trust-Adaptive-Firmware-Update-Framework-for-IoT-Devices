from pathlib import Path
import copy
import json
import pytest
import yaml
from witness.checkpoint import verify_checkpoint
from witness.client import Client
from witness.proof import verify_certificate

BASE=Path(__file__).resolve().parents[1]


def test_compose_private_seven_member_topology():
    config=yaml.safe_load((BASE/"compose.yaml").read_text())
    services=config["services"]
    assert {k for k in services if k.startswith("witness-")}=={f"witness-{i}" for i in range(1,8)}
    private=[]
    for i in range(1,8):
        node=services[f"witness-{i}"]
        assert not node.get("ports") and node["read_only"]
        assert node["cap_drop"]==["ALL"]
        assert node["networks"]==["witness"]
        mounts=node["volumes"]
        assert len(mounts)==4
        assert f"./runtime/docker/secrets/node-{i}.json:/runtime/secrets/node-{i}.json:ro" in mounts
        assert not any("client.json" in v or "admin.json" in v or "docker.sock" in v for v in mounts)
        private.append(next(v for v in mounts if "/data/" in v))
    assert len(set(private))==7
    assert config["networks"]["witness"]["internal"]


def test_exported_checkpoint_tamper_rejected():
    path=BASE/"reports/checkpoint.json"
    if not path.exists():pytest.skip("live checkpoint not exported")
    config=Client(BASE/"runtime/local").config
    proof=json.loads(path.read_text())
    assert verify_checkpoint(proof,config)["height"]>0
    bad=copy.deepcopy(proof);bad["approvals"][1]=bad["approvals"][0]
    with pytest.raises(ValueError):verify_checkpoint(bad,config)
    bad=copy.deepcopy(proof);bad["snapshot"]="e30="
    with pytest.raises(ValueError):verify_checkpoint(bad,config)


def test_saved_result_certificate_top_level_cannot_be_changed():
    paths=list((BASE/"runtime/local/client-events").glob("*.certificate.json"))
    if not paths:pytest.skip("live certificate not exported")
    config=Client(BASE/"runtime/local").config
    proof=json.loads(paths[0].read_text())
    command=proof["result"]["event"]["command"]
    assert verify_certificate(proof,command,config)["ok"]
    bad=copy.deepcopy(proof);bad["result"]["height"]+=1
    with pytest.raises(ValueError):verify_certificate(bad,command,config)
