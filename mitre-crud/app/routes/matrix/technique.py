from fastapi import APIRouter, Request, Path, HTTPException
from app.services.repository_service import RepositoryService

technique_router = APIRouter(prefix="/{tactic_id}/techniques")

@technique_router.get(
    "/",
    description="retrieving all techniques for given tactic",
)
def retrieve_all_techniques(request: Request, tactic_id: str = Path(..., description="Parent tactic ID")):
    techniques =  RepositoryService.get_techniques_per_tactic(tactic_id, request.state.domain)
    extracted_attack_id_name = {"tactics": [[technique["attack_id"], technique["name"]] for technique in techniques]}
    return extracted_attack_id_name

@technique_router.get(
    "/{technique_id}",
    description="retrieving all info specific technique",
)
def retrieve_technique_details(
    technique_id: str = Path(..., description="Parent tactic ID"),
):
    return RepositoryService.get_model_attack_id("Technique", technique_id)