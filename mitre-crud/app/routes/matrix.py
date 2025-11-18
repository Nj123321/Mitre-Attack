from fastapi import APIRouter, Request, Path, HTTPException, Depends
from app.services.repository_service import RepositoryService
from .tactics import tactic_router
from . import _domain_scope as ds

router = APIRouter(
    prefix="/matrix",
)

@router.get(
    "/domains",
    description="retrieve valid domains",
)
def retrieve_valid_domains():
    return list(ds.ALLOWED_DOMAINS.keys())

@router.get(
    "/{domain}",
    description="retireving attack matrix and related tactics, techniques at another endpoint",
)
def retrieve_matrix(domain: str = Depends(ds.valid_domain)):
    matrix_query =  RepositoryService.get_matrix(domain)
    if matrix_query is None:
        raise HTTPException(
            status_code=404,
            detail=f"unable to find matrix for domain: '{domain}'"
        )
    matrix_formatted = {}
    for matrix in matrix_query:
        matrix_formatted = {"matrix": matrix[0]._properties, }
        tactics = []
        for tactic_group in matrix[1]:
            techniques = []
            for technique_batch in tactic_group.get("techniques", []):
                sub_techniques = []
                # print(technique_batch)
                for sub_technique in technique_batch.get("subtechniques", []):
                    sub_techniques.append({
                        "subtechnique_name": sub_technique["name"],
                        "subtechnique_uuid": sub_technique["stix_uuid"],
                        "subtechnique_attack_id": sub_technique["attack_id"],
                    })
                techniques.append({
                    "technique_name": technique_batch["technique"]["name"],
                    "technique_uuid": technique_batch["technique"]["stix_uuid"],
                    "technique_attack_id": technique_batch["technique"]["attack_id"],
                    "sub_techniques": sub_techniques
                })
            tactic_formatted = {
                "tactic_name": tactic_group["tactic"]["name"],
                "tactic_uuid": tactic_group["tactic"]["stix_uuid"],
                "tactic_attack_id": tactic_group["tactic"]["attack_id"],
                "techniques": techniques
            }
            tactics.append(tactic_formatted)
        matrix_formatted["tactics"] = tactics
    return matrix_formatted

router.include_router(tactic_router)
