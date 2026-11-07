"""EVM address validation and canonicalization."""

from __future__ import annotations

import re

_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")


def normalize_evm_address(address: str) -> str:
    """Validate an EVM address's 20-byte hex shape and lowercase it.

    This intentionally does not verify the optional EIP-55 checksum yet.
    """
    if not isinstance(address, str):
        raise ValueError("EVM recipient must be a string address.")
    candidate = address.strip()
    if not _EVM_ADDRESS.fullmatch(candidate):
        raise ValueError("EVM recipient must be a 20-byte hexadecimal address.")
    return candidate.lower()
