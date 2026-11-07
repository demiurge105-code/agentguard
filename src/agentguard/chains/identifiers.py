"""Validation for chain identifiers used by AgentGuard."""

from __future__ import annotations

import re

_EIP155_CHAIN_ID = re.compile(r"eip155:(?:0|[1-9][0-9]{0,31})\Z")


def normalize_chain_id(chain_id: str | None) -> str | None:
    """Validate and canonicalize a supported CAIP-2 chain identifier.

    None is the backwards-compatible legacy mode. At this stage only
    positive decimal EIP-155 chain references are supported.
    """
    if chain_id is None:
        return None
    if not isinstance(chain_id, str) or not _EIP155_CHAIN_ID.fullmatch(chain_id):
        raise ValueError(
            "chain_id must be a supported EVM CAIP-2 identifier such as 'eip155:1'."
        )
    namespace, reference = chain_id.split(":", 1)
    if int(reference) <= 0:
        raise ValueError("EVM chain_id must use a positive chain reference.")
    return f"{namespace}:{reference}"
