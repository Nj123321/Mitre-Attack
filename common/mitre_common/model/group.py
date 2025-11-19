from ._mitre_base import *

class Group(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    aliases = JSONProperty()
    created_by_ref = StringProperty()
    description = StringProperty()
    external_references = JSONProperty()
    object_marking_refs = JSONProperty()
    revoked = BooleanProperty()
    spec_version = StringProperty()
    x_mitre_contributors = JSONProperty()
    x_mitre_deprecated = BooleanProperty()
    x_mitre_domains = JSONProperty()
    x_mitre_modified_by_ref = StringProperty()
    x_mitre_version = StringProperty()