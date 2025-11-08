from fastapi import APIRouter

@router.get("/{model_name}")
def get_model(model_name: str):
    return {"model": model_name}

@router.get("/{model_name}/details")
def get_model_details(model_name: str):
    return {"details_for": model_name}

from fastapi import FastAPI, HTTPException, Query
from model.base_object import VersionedObject
import json

router = APIRouter(prefix="/models")

ALLOWED_RESOURCES = {
    "analytic",
    "campaign",
    "collection",
    "data_component",
    "data_source",
    "detection_strategy",
    "group",
    "malware",
    "matrix",
    "mitigation",
    "sub_technique",
    "tactic",
    "technique",
    "tool",
}


@app.get("/models/{resource}")
def get_model(resource: str, uuid: str = Query(..., description="UUID of the object")):
    """
    Example route: /models/technique?uuid=1234-5678
    """
    if resource not in ALLOWED_RESOURCES:
        raise HTTPException(status_code=404, detail=f"Unknown resource '{resource}'")

    print(uuid)
    found_object = VersionedObject.nodes.get(attack_uuid=uuid)
    return found_object.__properties__