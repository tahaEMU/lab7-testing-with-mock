from unittest import mock
import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher, OperatorType
from presidio_anonymizer.entities import InvalidParamError


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(mock_encrypt):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text
    mock_encrypt.assert_called_once()


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(mock_encrypt):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": b"1111111111111111"})

    assert anonymized_text == expected_anonymized_text
    mock_encrypt.assert_called_once()


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    # 16 chars => 128 bits when UTF-8 encoded
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    # 16 bytes => 128 bits
    Encrypt().validate(params={"key": b"1111111111111111"})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    # "key" => 3 chars (not 16/24/32)
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})


@mock.patch.object(AESCipher, "is_valid_key_size", return_value=False)
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid):
    # Normally 16 bytes is valid, but we force the validator to return False
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b"1111111111111111"})
    mock_is_valid.assert_called()


def test_operator_name():
    assert Encrypt().operator_name() == "encrypt"


def test_operator_type():
    assert Encrypt().operator_type() == OperatorType.Anonymize


@pytest.mark.parametrize(
    "key",
    [
        # strings (UTF-8 -> bytes): 16/24/32 chars => 128/192/256 bits
        "A" * 16,
        "B" * 24,
        "C" * 32,
        # bytes: 16/24/32 bytes => 128/192/256 bits
        b"1" * 16,
        b"2" * 24,
        b"3" * 32,
    ],
)
def test_valid_keys(key):
    # Black-box: validate should accept all documented key sizes
    Encrypt().validate(params={"key": key})
