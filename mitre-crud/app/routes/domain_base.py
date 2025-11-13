# routers/domain_router.py
from fastapi import APIRouter, Depends, Path, Request, HTTPException, status
from . import models, matrix


ALLOWED_DOMAINS = {
    "enterprise": "enterpriseattack", 
    "mobile": "mobileattack",
    "ics": "icsattack"
}


async def get_domain(request: Request, domain: str = Path(...)):
    if domain not in ALLOWED_DOMAINS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{domain}' not allowed"
        )
    request.state.domain = ALLOWED_DOMAINS[domain]
    return domain

router = APIRouter(
    prefix="/{domain}",
    dependencies=[Depends(get_domain)]
)

router.include_router(matrix.router)
router.include_router(models.router)