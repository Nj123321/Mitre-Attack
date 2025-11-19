from ._mitre_base import *
from .relationship import RelationshipModel
class Matrix(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    contains = RelationshipTo('.tactic.Tactic', 'CONTAINS', model=RelationshipModel)
    
    created_by_ref = StringProperty()
    external_references = JSONProperty()
    object_marking_refs = JSONProperty()
    spec_version = StringProperty()
    x_mitre_deprecated = BooleanProperty()
    x_mitre_domains = JSONProperty()
    x_mitre_modified_by_ref = StringProperty()
    x_mitre_version = StringProperty()