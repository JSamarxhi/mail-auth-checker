"""
Mail authentication record checker.

Takes a domain, looks up its SPF, DKIM and DMARC records in DNS, and reports
what is missing or misconfigured.
"""

from typing import Optional

import dns.exception
import dns.resolver
from fastapi import FastAPI
from pydantic import BaseModel

# DKIM records live at <selector>._domainkey.<domain>. There is no way to
# discover selectors from DNS -- there is no record that lists them. You either
# know the selector or you guess it. These are the defaults the major senders
# use, which is why a checker like this can find anything at all.
COMMON_DKIM_SELECTORS = [
    "selector1",  # Microsoft 365
    "selector2",  # Microsoft 365
    "google",     # Google Workspace
    "k1",         # Mailchimp / Mandrill
    "s1",         # SendGrid and others
    "s2",
    "dkim",       # generic
    "default",    # generic
    "mail",       # generic
    "zoho",       # Zoho Mail
]

# A resolver with explicit timeouts. The defaults are generous, and a batch of
# domains where several are dead would otherwise hang for a long time.
RESOLVER = dns.resolver.Resolver()
RESOLVER.timeout = 3.0   # seconds to wait for a single nameserver to answer
RESOLVER.lifetime = 6.0  # total seconds before the whole query gives up


class DNSLookupFailed(Exception):
    """The lookup itself failed -- as opposed to succeeding and finding nothing.

    This distinction matters. "This domain has no SPF record" and "I could not
    reach a nameserver to find out" look identical if you swallow every error,
    and only one of them is the domain owner's problem.
    """


def txt_records(name: str) -> list[str]:
    """Return every TXT record at `name`. Empty list means the name resolved
    but has no TXT records, or does not exist at all."""
    try:
        answer = RESOLVER.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # NXDOMAIN: the name does not exist.
        # NoAnswer:  the name exists but has no records of this type.
        # Both are legitimate "nothing here" results, not failures.
        return []
    except dns.exception.DNSException as exc:
        # Timeouts, no reachable nameserver, malformed responses.
        raise DNSLookupFailed(f"{type(exc).__name__} looking up {name}") from exc

    records = []
    for rdata in answer:
        # A TXT record is a *list* of strings, not one string, because DNS caps
        # each individual string at 255 bytes. Anything longer arrives
        # pre-split and has to be rejoined with no separator. DKIM public keys
        # are routinely long enough to hit this.
        records.append("".join(chunk.decode() for chunk in rdata.strings))
    return records


def check_spf(domain: str) -> dict:
    """SPF: which hosts are allowed to send mail for this domain.

    Published as a TXT record at the domain itself, starting 'v=spf1'.
    """
    try:
        records = txt_records(domain)
    except DNSLookupFailed as exc:
        return {"status": "error", "record": None, "findings": [str(exc)]}

    spf = [r for r in records if r.lower().startswith("v=spf1")]

    if not spf:
        return {
            "status": "fail",
            "record": None,
            "findings": [
                "No SPF record. Receivers have no way to tell which hosts may "
                "send for this domain."
            ],
        }

    findings = []
    record = spf[0]

    if len(spf) > 1:
        findings.append(
            f"{len(spf)} SPF records published. RFC 7208 permits exactly one; "
            "receivers are required to treat multiple records as a permanent "
            "error, which fails every message."
        )

    # The 'all' mechanism is the catch-all at the end of the record: what a
    # receiver should do with a sender that matched nothing before it.
    if "+all" in record:
        findings.append(
            "'+all' passes every sender on the internet. Functionally identical "
            "to publishing no SPF record, but harder to notice."
        )
    elif "-all" in record:
        pass  # hardfail: the enforcing posture, nothing to report
    elif "~all" in record:
        findings.append(
            "'~all' (softfail) asks receivers to accept but mark. It is the "
            "monitoring posture; '-all' is the enforcing one."
        )
    elif "?all" in record:
        findings.append("'?all' (neutral) asserts nothing at all about unmatched senders.")
    else:
        findings.append(
            "No 'all' mechanism, so unmatched senders default to neutral."
        )

    # SPF allows at most 10 mechanisms that themselves trigger a DNS lookup.
    # Exceeding it is a permanent error, and it is the single most common way a
    # working SPF record silently stops working as a company adds vendors.
    #
    # Note this only counts the top level. Each 'include:' pulls in another
    # record whose own lookups count against the same budget, so a record that
    # passes this check can still bust the limit once expanded. Recursing is a
    # reasonable thing to add later.
    lookups = 0
    for token in record.split():
        t = token.lower().lstrip("+-~?")
        if t.startswith(("include:", "exists:", "redirect=", "a:", "mx:", "ptr:")):
            lookups += 1
        elif t in ("a", "mx", "ptr"):
            lookups += 1

    if lookups > 10:
        findings.append(
            f"{lookups} DNS-querying mechanisms at the top level. The limit is "
            "10; over it, receivers return permerror and SPF stops working."
        )
    elif lookups > 7:
        findings.append(
            f"{lookups} DNS-querying mechanisms at the top level, against a "
            "limit of 10. Nested includes count too, so this is close."
        )

    return {
        "status": "pass" if not findings else "warn",
        "record": record,
        "findings": findings,
    }


def parse_tags(record: str) -> dict:
    """Parse a 'k=v; k=v' style record (DMARC and DKIM both use this)."""
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(domain: str) -> dict:
    """DMARC: what to do when SPF and DKIM disagree with the From: header.

    Published as a TXT record at _dmarc.<domain>, starting 'v=DMARC1'.
    """
    name = f"_dmarc.{domain}"
    try:
        records = txt_records(name)
    except DNSLookupFailed as exc:
        return {"status": "error", "record": None, "findings": [str(exc)]}

    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]

    if not dmarc:
        return {
            "status": "fail",
            "record": None,
            "findings": [
                f"No DMARC record at {name}. Without it, SPF and DKIM results "
                "carry no instruction, and nobody reports abuse back to you."
            ],
        }

    record = dmarc[0]
    tags = parse_tags(record)
    findings = []

    if len(dmarc) > 1:
        findings.append(
            f"{len(dmarc)} DMARC records published. Receivers discard the whole "
            "policy when more than one exists."
        )

    policy = tags.get("p")
    if policy is None:
        findings.append("No 'p=' tag. The record is invalid without one.")
    elif policy == "none":
        findings.append(
            "'p=none' is monitoring only. Failing mail is still delivered, so "
            "this publishes visibility, not enforcement."
        )
    elif policy not in ("quarantine", "reject"):
        findings.append(f"'p={policy}' is not a valid policy value.")

    if "rua" not in tags:
        findings.append(
            "No 'rua=' address, so no aggregate reports. Enforcing without "
            "reports means finding out about broken senders from users."
        )

    pct = tags.get("pct")
    if pct and pct != "100":
        findings.append(
            f"'pct={pct}' applies the policy to only {pct}% of failing mail. "
            "Fine as a rollout step, a problem if it was forgotten."
        )

    return {
        "status": "pass" if not findings else "warn",
        "record": record,
        "policy": policy,
        "findings": findings,
    }


def check_dkim(domain: str, selectors: list[str]) -> dict:
    """DKIM: the public key receivers use to verify a message signature.

    Published at <selector>._domainkey.<domain>. Many providers put a CNAME
    there pointing at a key they host; the resolver follows it transparently,
    so a CNAME'd selector looks the same as a directly published one here.
    """
    found = {}
    errors = []

    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        try:
            records = txt_records(name)
        except DNSLookupFailed as exc:
            errors.append(str(exc))
            continue

        for record in records:
            # Some publishers omit the optional 'v=DKIM1' tag, so the presence
            # of a 'p=' public key tag is the more reliable signal.
            if "v=dkim1" in record.lower() or "p=" in record:
                found[selector] = record
                break

    if not found:
        return {
            "status": "fail" if not errors else "error",
            "selectors_found": {},
            "findings": [
                "No DKIM key found at any of the selectors tried: "
                + ", ".join(selectors)
                + ". This does not prove DKIM is absent -- selectors cannot be "
                "enumerated from DNS, so a custom one would be invisible here."
            ]
            + errors,
        }

    findings = []
    for selector, record in found.items():
        tags = parse_tags(record)
        if tags.get("p") == "":
            findings.append(
                f"Selector '{selector}' has an empty 'p=' tag, which is the "
                "documented way to revoke a key. Signatures using it will fail."
            )

    return {
        "status": "pass" if not findings else "warn",
        "selectors_found": found,
        "findings": findings,
    }


def check_domain(domain: str, selectors: Optional[list[str]] = None) -> dict:
    """Run all three checks and roll the results up into one verdict."""
    selectors = selectors or COMMON_DKIM_SELECTORS
    domain = domain.strip().lower().rstrip(".")

    results = {
        "domain": domain,
        "spf": check_spf(domain),
        "dkim": check_dkim(domain, selectors),
        "dmarc": check_dmarc(domain),
    }

    # Worst individual status wins, in this order.
    statuses = [results[k]["status"] for k in ("spf", "dkim", "dmarc")]
    for level in ("error", "fail", "warn"):
        if level in statuses:
            results["status"] = level
            break
    else:
        results["status"] = "pass"

    return results


app = FastAPI(
    title="Mail Authentication Record Checker",
    description="Reports SPF, DKIM and DMARC posture for a domain.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict:
    """Liveness check. nginx, Docker and Azure all want one of these later."""
    return {"status": "ok"}


@app.get("/check/{domain}")
def check_one(domain: str, selectors: Optional[str] = None) -> dict:
    """Check a single domain.

    Optional ?selectors=sel1,sel2 overrides the built-in DKIM selector list.
    """
    custom = [s.strip() for s in selectors.split(",")] if selectors else None
    return check_domain(domain, custom)


class BatchRequest(BaseModel):
    """Body schema for POST /check. FastAPI validates against this and returns
    a 422 with details if the caller sends something else."""

    domains: list[str]
    selectors: Optional[list[str]] = None


@app.post("/check")
def check_many(request: BatchRequest) -> dict:
    """Check several domains in one call."""
    return {
        "results": [check_domain(d, request.selectors) for d in request.domains]
    }


if __name__ == "__main__":
    # Lets the app run with a plain `python app.py`. In production nothing uses
    # this path -- systemd (step 3) and the container (step 4) both invoke
    # uvicorn directly, which is why the import string is spelled out here too.
    import uvicorn

    # Bound to loopback on purpose. Nothing outside this VM can reach it, which
    # is the correct posture once nginx is the only thing listening publicly.
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
