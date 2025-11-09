from fastapi import APIRouter

router = APIRouter(prefix="/matrix")

@router.get("/")
def retrieve_matrix():
    return {"users": ["alice", "bob"]}

@router.get("/tactics")
def retrieve_tactics():
    return {"users": ["alice", "bob"]}