from .base_object import *
from ._mitre_base import MitreBase

class Group(VersionedObject, MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]