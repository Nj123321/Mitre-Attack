from .base_object import *
from ._mitre_base import MitreBase

class DataSource(VersionedObject, MitreBase):
    __optional_labels__ = [
        "NetworkDevices",
        "SaaS",
        "OfficeSuite",
        "IdentityProvider",
        "Windows",
        "Containers",
        "iOS",
        "PRE",
        "Android",
        "macOS",
        "IaaS",
        "Linux",
        "ESXi",
        
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]