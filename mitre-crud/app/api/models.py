from fastapi import APIRouter, HTTPException, Query
from lib.model import *

router = APIRouter(prefix="/models")

ALLOWED_RESOURCES = {model.__name__: model for model in MODEL_LIST}
print(ALLOWED_RESOURCES)

@router.get("/{resource}")
def get_model(resource: str, uuid: str = Query(..., description="UUID of the object")):
    """
    Example route: /models/technique?uuid=1234-5678
    """
    print("found endpoint")
    if resource not in ALLOWED_RESOURCES:
        raise HTTPException(status_code=404, detail=f"Unknown resource '{resource}'")

    found_object = ALLOWED_RESOURCES[resource].nodes.get(attack_uuid=uuid)
    return found_object.__properties__

@router.get("/{model_name}/details")
def get_model_details(model_name: str):
    return {"details_for": model_name}