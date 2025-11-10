from .base_object import *
from ._mitre_base import MitreBase

class Tool(VersionedObject, MitreBase):
    __optional_labels__ = [
        "OfficeSuite",
        "IdentityProvider",
        "Windows",
        "Containers",
        "Android",
        "macOS",
        "IaaS",
        "Linux",
        
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]