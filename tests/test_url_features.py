import pytest

from src.url_features import URLValidationError, extract_features, normalize_url


def test_extracts_features_for_https_url():
    features = extract_features("https://docs.example.com/path?q=one&next=two")
    assert features["uses_https"] == 1
    assert features["hostname_length"] == len("docs.example.com")
    assert features["subdomain_count"] == 1
    assert features["query_parameter_count"] == 2


def test_ip_http_and_https_are_detected():
    assert extract_features("http://192.0.2.10/login")["is_ip_address"] == 1
    assert extract_features("http://example.test")["uses_https"] == 0
    assert extract_features("https://example.test")["uses_https"] == 1


@pytest.mark.parametrize(
    "value",
    ["", "example.test", "ftp://example.test", "https://", "https:// bad.test", "https://example.test:bad"],
)
def test_malformed_urls_are_rejected(value):
    with pytest.raises(URLValidationError):
        normalize_url(value)


def test_overlong_input_is_rejected():
    with pytest.raises(URLValidationError, match="2048"):
        normalize_url("https://example.test/" + "a" * 2048)


def test_ipv6_and_credentials_edge_cases():
    assert extract_features("https://[2001:db8::1]/")["is_ip_address"] == 1
    features = extract_features("https://user:pass@example.test/")
    assert features["has_credentials"] == 1
    assert features["has_at_symbol"] == 1


def test_punycode_and_shortener_are_detected():
    assert extract_features("https://xn--e1afmkfd.example/")["has_punycode"] == 1
    assert extract_features("https://bit.ly/abc")["is_shortened"] == 1
