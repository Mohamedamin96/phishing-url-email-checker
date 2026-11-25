from analyzer import analyze_url, analyze_email


def test_normal_url():
    result = analyze_url("https://example.com")

    assert result["score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["findings"] == []


def test_url_shortener():
    result = analyze_url("https://bit.ly/test")

    assert result["score"] == 15
    assert "URL shortener detected" in result["findings"]


def test_punycode_url():
    result = analyze_url("https://xn--example-test.com")

    assert result["score"] >= 30
    assert "Punycode detected" in result["findings"]


def test_ip_address_url():
    result = analyze_url("http://192.168.1.100/login")

    assert result["score"] >= 30
    assert "IP address URL" in result["findings"]


def test_excessive_subdomains():
    result = analyze_url(
        "https://login.security.account.verify.example.com"
    )

    assert result["score"] >= 15
    assert "Excessive subdomains" in result["findings"]


def test_email_spf_fail():
    headers = """
    Authentication-Results: spf=fail
    """

    result = analyze_email(headers)

    assert result["score"] == 20
    assert "SPF failed" in result["findings"]


def test_email_dkim_fail():
    headers = """
    Authentication-Results: dkim=fail
    """

    result = analyze_email(headers)

    assert result["score"] == 20
    assert "DKIM failed" in result["findings"]


def test_email_dmarc_fail():
    headers = """
    Authentication-Results: dmarc=fail
    """

    result = analyze_email(headers)

    assert result["score"] == 25
    assert "DMARC failed" in result["findings"]


def test_all_email_authentication_fail():
    headers = """
    Authentication-Results:
    spf=fail;
    dkim=fail;
    dmarc=fail
    """

    result = analyze_email(headers)

    assert result["score"] == 65
    assert result["risk_level"] == "HIGH"
    assert "SPF failed" in result["findings"]
    assert "DKIM failed" in result["findings"]
    assert "DMARC failed" in result["findings"]


def test_valid_email_authentication():
    headers = """
    Authentication-Results:
    spf=pass;
    dkim=pass;
    dmarc=pass
    """

    result = analyze_email(headers)

    assert result["score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["findings"] == []