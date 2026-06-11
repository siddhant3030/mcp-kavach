from mcp_kavach.detectors.checksums import luhn_valid, verhoeff_check_digit, verhoeff_valid


class TestVerhoeff:
    def test_canonical_vector(self):
        # Worked example from the Verhoeff algorithm literature: 236 -> check digit 3.
        assert verhoeff_check_digit("236") == 3
        assert verhoeff_valid("2363")
        assert not verhoeff_valid("2364")

    def test_generated_numbers_validate(self):
        for payload in ["23456789012", "98765432109", "45612378901", "78901234560"]:
            number = payload + str(verhoeff_check_digit(payload))
            assert verhoeff_valid(number), number

    def test_single_digit_perturbation_fails(self):
        number = "234567890124"
        assert verhoeff_valid(number)
        for i in range(len(number)):
            wrong = number[:i] + str((int(number[i]) + 1) % 10) + number[i + 1 :]
            assert not verhoeff_valid(wrong), wrong

    def test_ignores_separators(self):
        assert verhoeff_valid("2345 6789 0124")
        assert verhoeff_valid("2345-6789-0124")

    def test_empty_and_non_digit(self):
        assert not verhoeff_valid("")
        assert not verhoeff_valid("abc")


class TestLuhn:
    def test_known_valid_cards(self):
        assert luhn_valid("4111111111111111")
        assert luhn_valid("4111 1111 1111 1111")
        assert luhn_valid("5500005555555559")

    def test_perturbation_fails(self):
        assert not luhn_valid("4111111111111112")

    def test_too_short(self):
        assert not luhn_valid("0")
        assert not luhn_valid("")
