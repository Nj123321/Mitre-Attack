from .base_object import *
from ._mitre_base import MitreBase

class Matrix(VersionedObject, MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    contains = RelationshipTo('.tactic.Tactic', 'CONTAINS')