from .base_object import *

class SubTechnique(VersionedObject):
    name = StringProperty(required=True)