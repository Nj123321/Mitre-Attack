from ._mitre_base import *

class DataComponent(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    created_by_ref = StringProperty()
    description = StringProperty()
    external_references = JSONProperty()
    object_marking_refs = JSONProperty()
    revoked = StringProperty()
    spec_version = StringProperty()
    x_mitre_data_source_ref = StringProperty()
    x_mitre_deprecated = StringProperty()
    x_mitre_domains = JSONProperty()
    x_mitre_modified_by_ref = StringProperty()
    x_mitre_version = StringProperty()