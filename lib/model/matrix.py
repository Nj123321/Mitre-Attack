from .base_object import *
from ._mitre_base import MitreBase

class Matrix(VersionedObject, MitreBase):
    contains = RelationshipTo('.tactic.Tactic', 'CONTAINS')