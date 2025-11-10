from .base_object import *
from ._mitre_base import MitreBase

class Tactic(VersionedObject, MitreBase):
    name = StringProperty(required=True, unique_index=True)