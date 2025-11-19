from ._mitre_base import *

class Asset(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    created_by_ref = StringProperty()
    description = StringProperty()
    external_references = JSONProperty()
    object_marking_refs = JSONProperty()
    revoked = BooleanProperty()
    spec_version = StringProperty()
    x_mitre_deprecated = StringProperty()
    x_mitre_domains = JSONProperty()
    x_mitre_modified_by_ref = StringProperty()
    x_mitre_platforms = JSONProperty()
    x_mitre_related_assets = JSONProperty()
    x_mitre_sectors = JSONProperty()
    x_mitre_version = StringProperty()