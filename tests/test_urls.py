from recon.urls import dedupe_urls, normalize_url


def test_duplicate_url_cleanup():
    result = dedupe_urls(["HTTPS://Example.com/a", "https://example.com/a"])
    assert result["original_count"] == 2
    assert result["deduped_count"] == 1
    assert result["urls"] == ["https://example.com/a"]


def test_fragment_removal():
    assert normalize_url("https://example.com/a#section") == "https://example.com/a"


def test_query_sorting():
    assert normalize_url("https://example.com/a?b=2&a=1") == "https://example.com/a?a=1&b=2"


def test_default_port_removal():
    assert normalize_url("http://example.com:80/a") == "http://example.com/a"
    assert normalize_url("https://example.com:443/a") == "https://example.com/a"
