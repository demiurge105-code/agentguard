"""Chain-specific identifiers and address handling.

The first supported namespace is EVM (CAIP-2 eip155).
"""

from .identifiers import normalize_chain_id
from .evm import normalize_evm_address
from .recipients import normalize_recipient

__all__ = ["normalize_chain_id", "normalize_evm_address", "normalize_recipient"]
