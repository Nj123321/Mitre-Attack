from fastapi import APIRouter, Request, Path, HTTPException, Depends
from app.services.repository_service import RepositoryService
from .technique import technique_router
from . import _domain_scope as ds

tactic_router = APIRouter(prefix="/{domain}/tactics")

@tactic_router.get(
    "/",
    description="retrieving all tactics for given matrix",
)
def get_only_tactics(domain: str = Depends(ds.valid_domain)):
    tactics = RepositoryService.get_tacitcs_in_matrix(domain)
    response = {"tactics": [{ "attack_id": tactic["attack_id"], "name": tactic["name"]} for tactic in tactics]}
    return response

tactic_router.include_router(technique_router)