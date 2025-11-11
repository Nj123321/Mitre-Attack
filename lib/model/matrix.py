from ._mitre_base import *

class Matrix(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    contains = RelationshipTo('.tactic.Tactic', 'CONTAINS')