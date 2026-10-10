from __future__ import annotations

import hmac
from dataclasses import dataclass

from sentinel_core.config import Settings
from sentinel_core.errors import GateUnauthenticated


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    workspace_id: str
    principal_id: str
    display_name: str
    scopes: tuple[str, ...]


def authenticate(settings: Settings, presented: str | None) -> Principal:
    """M1 dev auth: static keys from config (Stage-6 auth service replaces
    this stub).  Constant-time compare over every configured key."""
    if not presented:
        raise GateUnauthenticated("missing API key")
    matched = None
    for dk in settings.dev_keys:
        if hmac.compare_digest(dk.key.encode(), presented.encode()):
            matched = dk
    if matched is None:
        raise GateUnauthenticated("invalid API key")
    return Principal(
        tenant_id=matched.tenant_id,
        workspace_id=matched.workspace_id,
        principal_id=matched.principal_id,
        display_name=matched.display_name,
        scopes=matched.scopes,
    )
