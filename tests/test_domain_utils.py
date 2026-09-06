import pytest

from web_guard.domain_utils import domain_matches, normalize_domain, suffixes


def test_normalizes_url_and_unicode():
    assert normalize_domain(" HTTPS://BÜCHER.de/path ") == "xn--bcher-kva.de"


@pytest.mark.parametrize("value", [
    "", "localhost", "127.0.0.1", "bad_domain.com", "example.com:443",
    "*.example.com", ".com", "example.comanything", "example.invalidtld",
    "example..com", "-example.com", "example-.com",
])
def test_rejects_unsafe_or_incomplete_values(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


def test_suffix_matching_includes_parent_but_not_public_suffix():
    assert suffixes("a.b.example.com") == ("a.b.example.com", "b.example.com", "example.com")
    assert domain_matches("a.example.com", {"example.com"})
    assert not domain_matches("example.com", {"com"})


@pytest.mark.parametrize("value", [
    "example.com", "sub.example.co.uk", "https://example.gov/path", "münchen.de",
])
def test_accepts_current_delegated_top_level_domains(value):
    assert normalize_domain(value)
