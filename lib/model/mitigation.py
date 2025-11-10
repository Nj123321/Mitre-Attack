from .base_object import *
from ._mitre_base import MitreBase

class Mitigation(VersionedObject, MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]