from .base_object import *
from ._mitre_base import MitreBase

class Tactic(VersionedObject, MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    name = StringProperty(required=True, unique_index=True)