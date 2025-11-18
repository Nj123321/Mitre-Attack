from fastapi import APIRouter, Request, Path, HTTPException
from app.services.repository_service import RepositoryService

technique_router = APIRouter(prefix="/{tactic_id}/techniques")

@technique_router.get(
    "/",
    description="retrieving all techniques for given tactic",
)
def retrieve_all_techniques(tactic_id: str = Path(..., description="Parent tactic ID")):
    techniques =  RepositoryService.get_techniques_per_tactic(tactic_id)
    extracted_attack_id_name = {"techniques": [[technique["attack_id"], technique["name"]] for technique in techniques]}
    return extracted_attack_id_name

@technique_router.get(
    "/{technique_id}/subtechniques",
    description="retrieving all subtechniques for given technique",
)
def retrieve_all_subtechniques(
    technique_id: str = Path(..., description="Technique ID")
):
    subtechniques =  RepositoryService.get_sub_techniques_per_technique(technique_id)
    extracted_attack_id_name = {"subtechniques": [{"attack_id": subtechnique["attack_id"], "name": subtechnique["name"]} for subtechnique in subtechniques]}
    return extracted_attack_id_name