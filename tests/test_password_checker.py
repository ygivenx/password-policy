import pytest
from passvalidate import PasswordPolicy


@pytest.fixture
def default_policy():
    return PasswordPolicy()


@pytest.fixture
def custom_policy():
    return PasswordPolicy(
        min_length=10,
        min_uppercase=1,
        min_lowercase=1,
        min_digits=1,
        min_special=1,
        special_chars="!@#$%^&*",
        allow_spaces=True
    )


def test_valid_password(default_policy):
    is_valid, issues = default_policy.check_password("P@ssw0rd!2")
    assert is_valid is True
    assert len(issues) == 0


def test_invalid_password(default_policy):
    is_valid, issues = default_policy.check_password("weak")
    assert is_valid is False
    assert len(issues) > 0


def test_custom_policy_valid(custom_policy):
    is_valid, issues = custom_policy.check_password("Pass word1!")
    assert is_valid is True
    assert len(issues) == 0


def test_custom_policy_invalid(custom_policy):
    is_valid, issues = custom_policy.check_password("password")
    assert is_valid is False
    assert len(issues) > 0


def test_get_policy_description(default_policy):
    description = default_policy.get_policy_description()
    assert len(description) == 7
    assert "Minimum length: 8" in description
