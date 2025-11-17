from ._mitre_base import *
from .relationship import RelationshipModel
class Matrix(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    contains = RelationshipTo('.tactic.Tactic', 'CONTAINS', model=RelationshipModel)