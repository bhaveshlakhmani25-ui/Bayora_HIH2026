"""Loads bayora/default.yaml, then overlays a user YAML file (zones merge key by key)."""
from importlib.resources import files
import yaml
from .drill import ENC, TENANT


def load(path=None):
    cfg = yaml.safe_load(files("bayora").joinpath("default.yaml").read_text())
    if path:
        with open(path) as f: user = yaml.safe_load(f) or {}
        if unknown := set(user) - set(cfg): raise ValueError(f"unknown config keys: {sorted(unknown)}")
        cfg.update({**user, "zones": {**cfg["zones"], **user.get("zones", {})}})
    if set(cfg["zones"]) != {"red", "blue", "model"}: raise ValueError("zones must be exactly red, blue, model")
    if bad := set(cfg["channels"]) - set(TENANT): raise ValueError(f"unknown channels: {sorted(bad)}; known: {sorted(TENANT)}")
    if bad := set(cfg["encodings"]) - set(ENC): raise ValueError(f"unknown encodings: {sorted(bad)}; known: {sorted(ENC)}")
    if cfg["enforcer"] not in ("auto", "ebpf", "docker"): raise ValueError("enforcer must be auto, ebpf or docker")
    return cfg
