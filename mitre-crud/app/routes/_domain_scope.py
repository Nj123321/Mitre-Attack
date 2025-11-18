from fastapi import Path, HTTPException

ALLOWED_DOMAINS = {
    "enterprise": "enterprise-attack",
    "mobile": "mobile-attack",
    "ics": "ics-attack"
}

def valid_domain(domain: str = Path(...)):
    if domain not in ALLOWED_DOMAINS:
        raise HTTPException(
            status_code=404,
            detail=f"invalid domain: '{domain}'"
        )
    return ALLOWED_DOMAINS[domain]