from fastapi import APIRouter

router = APIRouter(prefix="/matrix")

@router.get("/")
def retrieve_tactics():
    return {"users": ["alice", "bob"]}