import pytest
from password_policy import PasswordPolicy


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
    assert default_policy.check_password("P@ssw0rd!2") is True


def test_invalid_password(default_policy):
    assert default_policy.check_password("weak") is False


def test_password_issues(default_policy):
    issues = default_policy.get_password_strength_issues("weak")
    assert len(issues) > 0
    assert any("needs to be at least" in issue for issue in issues)


def test_custom_policy_valid(custom_policy):
    assert custom_policy.check_password("Pass word1!") is True


def test_custom_policy_invalid(custom_policy):
    assert custom_policy.check_password("password") is False


def test_get_policy_description(default_policy):
    description = default_policy.get_policy_description()
    assert len(description) == 7
    assert "Minimum length: 8" in description
