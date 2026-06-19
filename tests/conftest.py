import pytest

from virelia import Engine, load_preset

# Verhoeff-valid 12-digit numbers in Aadhaar format (synthetic, generated
# with detectors.checksums.verhoeff_check_digit).
VALID_AADHAAR = "234567890124"
VALID_AADHAAR_2 = "987654321096"
INVALID_AADHAAR = "234567890123"  # fails the checksum


@pytest.fixture
def ngo_policy():
    return load_preset("ngo-default")


@pytest.fixture
def engine(ngo_policy):
    return Engine(ngo_policy, hmac_salt=b"test-salt")
