from triage.analyzers.domains import (
    address_domain,
    display_name,
    is_lookalike,
    levenshtein,
    org_domain,
    same_org,
    unicode_form,
)


def test_address_domain_and_display_name():
    value = '"Microsoft 365 Admin" <No-Reply@M365-Account.example>'

    assert address_domain(value) == "m365-account.example"
    assert display_name(value) == "Microsoft 365 Admin"
    assert address_domain("<>") is None
    assert address_domain(None) is None


def test_org_domain_keeps_two_label_suffixes():
    assert org_domain("mail.news.contoso.example") == "contoso.example"
    assert org_domain("online.bank.com.tr") == "bank.com.tr"
    assert same_org("mail.contoso.example", "contoso.example")
    assert not same_org("contoso-invoices.example", "contoso.example")


def test_levenshtein():
    assert levenshtein("northwind", "northwind") == 0
    assert levenshtein("northwlnd", "northwind") == 1  # one substitution
    assert levenshtein("paypall", "paypal") == 1  # one insert
    assert levenshtein("kitten", "sitting") == 3


def test_lookalike_by_typo_and_by_confusable_letters():
    assert is_lookalike("northwlnd-traders.example", "northwind-traders.example")
    assert is_lookalike("rnicrosoft.com", "microsoft.com")  # "rn" looks like "m"
    assert is_lookalike("paypa1.com", "paypal.com")  # "1" looks like "l"
    assert not is_lookalike("microsoft.com", "microsoft.com")  # identical is not a lookalike
    assert not is_lookalike("contoso-invoices.example", "contoso.example")


def test_unicode_form_decodes_punycode():
    assert unicode_form("xn--mcrosoft-thh.example") == "mіcrosoft.example"  # Cyrillic i
    assert unicode_form("microsoft.com") is None
