from .base_object import *
from ._mitre_base import MitreBase

class Analytic(VersionedObject, MitreBase):
   __optional_labels__ = [
        "NetworkDevices",
        "SaaS",
        "OfficeSuite",
        "IdentityProvider",
        "Windows",
        "Containers",
        "PRE",
        "macOS",
        "IaaS",
        "Linux",
        "ESXi",
    ]