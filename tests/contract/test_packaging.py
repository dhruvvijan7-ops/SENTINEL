"""M1 exit ⑤ packaging contract.

Stage-6 §7.2 / D6-004: WinSW (MIT, VERIFIED) wraps the API and the worker;
NSSM is rejected and its licence is UNVERIFIED (OQ-6-09).  These tests pin the
installer surface so the service wrapper cannot silently regress — the live
clean-VM drill itself runs under packaging/drill.ps1.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / "packaging"

SERVICE_IDS = {"sentinel-api", "sentinel-worker"}
MODULES = {"sentinel-api": "-m sentinel_api.main", "sentinel-worker": "-m sentinel_worker.main"}
ALLOWED_TOKENS = {"{{PYTHON}}", "{{INSTALL_ROOT}}", "{{CONFIG}}", "{{LOG_DIR}}"}
PINNED_WIN_SW_URL = (
    "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe"
)
PINNED_WIN_SW_SHA256 = (
    "05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da"
)
_TOKEN = re.compile(r"\{\{[A-Z_]+\}\}")


def _templates() -> dict[str, ET.Element]:
    out: dict[str, ET.Element] = {}
    for path in sorted((PACKAGING / "winsw").glob("*.xml")):
        out[path.name] = ET.parse(path).getroot()
    return out


def test_both_winsw_templates_exist_and_name_the_two_services():
    templates = _templates()
    assert set(templates) == {"sentinel-api.xml", "sentinel-worker.xml"}
    ids = {root.findtext("id") for root in templates.values()}
    assert ids == SERVICE_IDS, f"service ids must be exactly {SERVICE_IDS}, got {ids}"


def test_every_template_starts_its_module():
    for name, root in _templates().items():
        sid = root.findtext("id")
        assert root.findtext("arguments") == MODULES[sid], name
        assert root.findtext("executable") == "{{PYTHON}}", name


def test_templates_only_use_allow_listed_tokens():
    for path in sorted((PACKAGING / "winsw").glob("*.xml")):
        found = set(_TOKEN.findall(path.read_text(encoding="utf-8")))
        assert found <= ALLOWED_TOKENS, f"{path.name}: unexpected tokens {found - ALLOWED_TOKENS}"
        assert found == ALLOWED_TOKENS, (
            f"{path.name}: template must consume all of {sorted(ALLOWED_TOKENS)}, "
            f"found {sorted(found)}"
        )


def test_templates_pin_working_directory_and_config():
    for path in sorted((PACKAGING / "winsw").glob("*.xml")):
        root = ET.parse(path).getroot()
        # The M0-era installer used the caller's cwd as the service working
        # directory; the render target is the install root instead.
        assert root.findtext("workingdirectory") == "{{INSTALL_ROOT}}", path.name
        env = {e.get("name"): e.get("value") for e in root.findall("env")}
        assert env.get("SENTINEL_CONFIG") == "{{CONFIG}}", path.name
        assert env.get("PYTHONIOENCODING") == "utf-8", path.name
        assert root.findtext("logpath") == "{{LOG_DIR}}", path.name


def test_templates_carry_a_restart_policy():
    for path in sorted((PACKAGING / "winsw").glob("*.xml")):
        root = ET.parse(path).getroot()
        onfailure = root.findall("onfailure")
        assert onfailure, f"{path.name} has no <onfailure> restart policy (§7.2)"
        assert {o.get("action") for o in onfailure} == {"restart"}
        assert root.findtext("startmode") == "Automatic"


def test_nssm_is_not_referenced_anywhere_in_packaging():
    hits = []
    for path in PACKAGING.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:  # pragma: no cover
            continue
        if re.search(r"nssm", text, re.IGNORECASE):
            hits.append(str(path.relative_to(ROOT)))
    assert not hits, (
        f"NSSM referenced in {hits}: D6-004 rejects it and OQ-6-09 leaves its "
        "licence UNVERIFIED, so WinSW is the only allowed wrapper"
    )


def test_installer_pins_the_winsw_release_url_and_sha256():
    text = (PACKAGING / "install.ps1").read_text(encoding="utf-8")
    assert PINNED_WIN_SW_URL in text, "WinSW download must be a pinned release URL"
    assert "latest" not in PINNED_WIN_SW_URL
    assert PINNED_WIN_SW_SHA256 in text, "WinSW download must be sha256-pinned"
    assert re.fullmatch(r"[0-9a-f]{64}", PINNED_WIN_SW_SHA256)
    assert "Get-FileHash" in text, "the pin must actually be verified on download"


def test_installer_creates_both_services_and_asserts_them():
    text = (PACKAGING / "install.ps1").read_text(encoding="utf-8")
    for sid in SERVICE_IDS:
        assert sid in text, f"install.ps1 never mentions {sid}"
    assert "Assert-ServiceRunning" in text
    assert "Assert-Health" in text
    assert "/health" in text
    assert "migrations.apply" in text, "installer must apply migrations (§9)"
    assert "Assert-Admin" in text


def test_installer_can_provision_the_three_roles():
    text = (PACKAGING / "install.ps1").read_text(encoding="utf-8")
    assert "ProvisionDatabase" in text, "§7.2: installer creates the roles"
    assert "00-roles.sql" in text
    roles = (PACKAGING / "docker-init" / "00-roles.sql").read_text(encoding="utf-8")
    for role in ("sentinel_app", "sentinel_migrator", "sentinel_worker"):
        assert role in roles, role


def test_uninstaller_uses_win_sw_verbs():
    text = (PACKAGING / "uninstall.ps1").read_text(encoding="utf-8")
    assert "uninstall" in text
    assert "Get-Service" in text
    assert re.search(r"sc\.exe\s+delete", text), "fallback removal must still work"


def test_drill_covers_exit_5_and_records_a_ledger():
    text = (PACKAGING / "drill.ps1").read_text(encoding="utf-8")
    for sid in SERVICE_IDS:
        assert sid in text, f"drill.ps1 never mentions {sid}"
    for needle in ("/health", "/ready", "Get-Service", "install.ps1", "uninstall"):
        assert needle in text, f"drill.ps1 does not exercise {needle}"
    assert "VERIFIED" in text and "FAILED" in text, "drill must print a verdict ledger"
    assert "-KeepServices" in text, "drill must be able to leave services for inspection"


def test_roles_script_is_idempotent():
    """docker initdb runs it once; install.ps1 -ProvisionDatabase re-runs it on
    every clean-VM install, so a second run must be a no-op."""
    roles = (PACKAGING / "docker-init" / "00-roles.sql").read_text(encoding="utf-8")
    assert roles.count("CREATE ROLE") == 3
    assert roles.upper().count("IF NOT EXISTS") == 3, "each CREATE ROLE must be guarded"
    assert roles.upper().count("IF EXISTS") >= 2, "grants must be guarded too"
    assert "pg_roles" in roles, "CREATE ROLE must be guarded by a pg_roles lookup"
    assert roles.count("DO $$") == 2


def test_installer_does_not_derive_the_working_directory_from_the_caller():
    """M0-era bug: the service AppDirectory was the shell's cwd, so the worker
    lost its relative paths the moment WinSW started it."""
    text = (PACKAGING / "install.ps1").read_text(encoding="utf-8")
    assert "Get-Location" not in text
    assert "$PWD" not in text
    assert "AppDirectory" not in text
