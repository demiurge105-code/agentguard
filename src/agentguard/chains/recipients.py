"""Recipient normalization selected by the policy's chain namespace."""

from __future__ import annotations

from .evm import normalize_evm_address
from .identifiers import normalize_chain_id


def normalize_recipient(recipient: str, chain_id: str | None = None) -> str:
    """Normalize a recipient using chain-specific semantics.

    Policies without a chain identifier retain the original case-insensitive
    legacy behavior. Explicit EVM policies require a valid EVM address.
    """
    normalized_chain_id = normalize_chain_id(chain_id)
    if not isinstance(recipient, str):
        raise ValueError("recipient identifiers must be strings.")
    if normalized_chain_id is None:
        normalized = recipient.strip().lower()
        if not normalized:
            raise ValueError("recipient identifiers must not be empty.")
        return normalized
    return normalize_evm_address(recipient)
