import os
import re

import yaml

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "service_manifest.yml")


def _manifest():
    with open(MANIFEST_PATH) as f:
        return yaml.safe_load(f)


def test_heuristic_filetypes_are_valid_regex():
    manifest = _manifest()
    for heuristic in manifest["heuristics"]:
        re.compile(heuristic["filetype"])


def test_accepts_and_rejects_are_valid_regex():
    manifest = _manifest()
    re.compile(manifest["accepts"])
    re.compile(manifest["rejects"])


def test_accepts_and_rejects_contain_no_lookaround():
    # Rust's `regex` crate (used by AL4's real dispatcher) doesn't support
    # look-around at all -- Python's `re` happily accepts it, so this is the only
    # thing that catches a regex that would crash dispatch cluster-wide on deploy.
    manifest = _manifest()
    for field in ("accepts", "rejects"):
        pattern = manifest[field]
        assert "(?=" not in pattern and "(?!" not in pattern and "(?<" not in pattern


def test_docker_image_matches_version_file():
    manifest = _manifest()
    version_path = os.path.join(os.path.dirname(__file__), "..", "..", "VERSION")
    with open(version_path) as f:
        version = f.read().strip()
    assert manifest["docker_config"]["image"] == "kylemc54321/assemblyline-service-vbssim:$SERVICE_TAG"
    assert re.match(r"^\d+\.\d+\.\d+\.stable\d+$", version)


def test_no_internet_access():
    manifest = _manifest()
    assert manifest["docker_config"]["allow_internet_access"] is False
