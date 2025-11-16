from fastapi import APIRouter, Request, Path, HTTPException
from app.services.repository_service import RepositoryService

technique_router = APIRouter(prefix="/{tactic_id}/techniques")

@technique_router.get(
    "/",
    description="retrieving all tactics",
)
def retrieve_all_techniques(request: Request, tactic_id: str = Path(..., description="Parent tactic ID")):
    return {"tatic_id": tactic_id}

@technique_router.get(
    "/{technique_id}",
    description="retrieving all info specific technique",
)
def retrieve_matrix(
    request: Request,
    tactic_id: str = Path(..., description="Parent tactic ID"),
    technique_id: str = Path(..., description="Tactic ID, e.g. TA0001")
):
    return {"tactic_id": tactic_id, "technique_id": technique_id}

# technique_router.include_router(technique_router)