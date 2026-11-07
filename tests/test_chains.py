import pytest

from agentguard.chains import normalize_chain_id, normalize_evm_address, normalize_recipient


@pytest.mark.parametrize("chain_id", ["eip155:1", "eip155:8453", "eip155:42161"])
def test_accepts_supported_evm_chain_identifiers(chain_id):
    assert normalize_chain_id(chain_id) == chain_id


@pytest.mark.parametrize(
    "chain_id",
    ["", "ethereum:1", "solana:mainnet", "eip155:0", "eip155:01", "eip155:-1", "eip155:1x"],
)
def test_rejects_unsupported_or_malformed_chain_identifiers(chain_id):
    with pytest.raises(ValueError, match="chain_id"):
        normalize_chain_id(chain_id)


def test_none_chain_id_selects_legacy_mode():
    assert normalize_chain_id(None) is None


def test_normalizes_valid_evm_address_to_lowercase():
    address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
    assert normalize_evm_address(address) == address.lower()


@pytest.mark.parametrize(
    "address",
    [
        "",
        "0x1234",
        "1234567890123456789012345678901234567890",
        "0xgggggggggggggggggggggggggggggggggggggggg",
        "0x12345678901234567890123456789012345678901",
    ],
)
def test_rejects_malformed_evm_addresses(address):
    with pytest.raises(ValueError, match="20-byte hexadecimal"):
        normalize_evm_address(address)


def test_legacy_recipient_normalization_remains_case_insensitive():
    assert normalize_recipient(" Alice ") == "alice"


def test_evm_recipient_normalization_is_chain_aware():
    address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
    assert normalize_recipient(address, "eip155:1") == address.lower()


def test_evm_recipient_does_not_accept_arbitrary_identifiers():
    with pytest.raises(ValueError, match="20-byte hexadecimal"):
        normalize_recipient("Alice", "eip155:1")
