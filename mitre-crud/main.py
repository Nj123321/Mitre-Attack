from fastapi import FastAPI
from model.base_object import VersionedObject
import json


app = FastAPI()

@app.get("/")
def root(tid: str):
    wtf = VersionedObject.nodes.get(attack_uuid="x-mitre-analytic--6b5b9cd2-f6ba-4ed5-bea2-30edbf85501e")
    print("holyomonly: " + tid)
    node = VersionedObject.nodes.get(attack_uuid=tid)

        # Pretty-print JSON
    # pretty_json = json.dumps(data, indent=4)  # indent=4 adds nice spacing
    # return json.dumps(node.__properties__, indent=2)
    return node.__properties__