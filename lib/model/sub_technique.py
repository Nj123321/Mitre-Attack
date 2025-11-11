from .technique import Technique

class SubTechnique(Technique):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]