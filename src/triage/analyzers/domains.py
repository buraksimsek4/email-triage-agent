"""Small, dependency-free helpers for comparing domain names."""

from email.utils import parseaddr

# Public suffixes with two labels that we expect to see. Without this, "bank.com.tr" would be
# treated as the organization "com.tr". A full Public Suffix List (tldextract) can replace this
# if the dataset ever needs it.
_TWO_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.tr", "org.tr", "gov.tr", "com.au", "co.jp"}

# Character sequences that look alike in most fonts. Mapping both sides to one "skeleton"
# makes "rnicrosoft" and "microsoft", or "northwlnd" and "northwind", compare equal.
_CONFUSABLES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("i", "l"), ("|", "l")]


def address_domain(header_value: str | None) -> str | None:
    """Domain part of the address in a From/Reply-To/Return-Path value, lowercased."""
    if not header_value:
        return None
    _, address = parseaddr(header_value)
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().strip(".").lower()
    return domain or None


def display_name(header_value: str | None) -> str:
    """The human-readable name in front of the address, e.g. "Microsoft 365 Admin"."""
    if not header_value:
        return ""
    name, _ = parseaddr(header_value)
    return name.strip()


def org_domain(domain: str) -> str:
    """Registrable ("organizational") domain: mail.news.example.com -> example.com."""
    labels = domain.lower().strip(".").split(".")
    keep = 3 if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES else 2
    return ".".join(labels[-keep:])


def same_org(domain_a: str, domain_b: str) -> bool:
    """Relaxed alignment, as DMARC defines it: same organizational domain."""
    return org_domain(domain_a) == org_domain(domain_b)


def levenshtein(a: str, b: str) -> int:
    """Number of single-character inserts, deletes or substitutions to turn a into b."""
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def skeleton(text: str) -> str:
    """Collapse look-alike characters so visually similar strings become identical."""
    result = text.lower()
    for look_alike, replacement in _CONFUSABLES:
        result = result.replace(look_alike, replacement)
    return result


def is_lookalike(candidate: str, protected: str) -> bool:
    """True if `candidate` is not `protected` but is one typo or one look-alike swap away."""
    if candidate == protected:
        return False
    return levenshtein(candidate, protected) == 1 or skeleton(candidate) == skeleton(protected)


def unicode_form(domain: str) -> str | None:
    """If the domain is internationalized (xn-- or non-ASCII), return its Unicode form."""
    if domain.isascii() and not any(label.startswith("xn--") for label in domain.split(".")):
        return None
    try:
        return domain.encode("ascii").decode("idna") if domain.isascii() else domain
    except UnicodeError:
        return domain  # malformed punycode is still an internationalized-looking domain
