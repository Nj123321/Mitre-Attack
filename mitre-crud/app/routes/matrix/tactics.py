from fastapi import APIRouter, Request, Path, HTTPException
from app.services.repository_service import RepositoryService
from .technique import technique_router

tactic_router = APIRouter(prefix="/tactics")

@tactic_router.get(
    "/",
    description="retrieving all tactics for given matrix",
)
def retrieve_matrix(request: Request):
    tactics = RepositoryService.get_tacitcs_in_matrix(request.state.domain)
    response = {"tactics": [[tactic["attack_id"], tactic["name"]] for tactic in tactics]}
    return response

@tactic_router.get(
    "/{tactic_id}",
    description="retrieving all info specific tactic",
)
def retrieve_matrix(
    request: Request,
    tactic_id: str = Path(..., description="Tactic ID, e.g. TA0001")
):
    return RepositoryService.get_model_attack_id("Tactic", tactic_id)

tactic_router.include_router(technique_router)