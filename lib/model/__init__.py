from .sub_technique import SubTechnique
from .technique import Technique
from .campaign import Campaign
from .mitigation import Mitigation
from .group import Group
from .relationship import Relationship
from .analytic import Analytic
from .collection import Collection
from .data_component import DataComponent
from .data_source import DataSource
from .detection_strategy import DetectionStrategy
from .matrix import Matrix
from .tactic import Tactic
from .malware import Malware
from .tool import Tool

# __all__ = [
#     "Analytic",
#     "BaseObject",
#     "SubTechnique",
#     "Tactic",
#     "Technique",
# ]

MODEL_LIST = [
    SubTechnique,
    Technique,
    Campaign,
    Mitigation,
    Group,
    Relationship,
    Analytic,
    Collection,
    DataComponent,
    DataSource,
    DetectionStrategy,
    Matrix,
    Tactic,
    Malware,
    Tool,
]

def find_model_from_json(model_json, delete=False):
    print("matching model for: " + str(model_json))
    model_type = model_json["type"]
    print()
    try:
        match model_type:
            # stix object data
            case "attack-pattern":
                if delete:
                    return Technique
                if model_json["x_mitre_is_subtechnique"] == True:
                    return SubTechnique
                return Technique
            case "campaign":
                return Campaign
            case "course-of-action":
                return Mitigation
            # case "Identity":
                # return 
            case "intrusion-set":
                return Group
            case "malware":
                #software with tool?
                return Malware
            case "tool":
                #software with tool?
                return Tool
            # case "MarkingDefinition":
                # pass
            case "relationship":
                return Relationship
            
            # custom stix types
            case "x-mitre-analytic":
                return Analytic
            case "x-mitre-collection":
                return Collection
            case "x-mitre-data-component":
                return DataComponent
            case "x-mitre-data-source":
                return DataSource
            case "x-mitre-detection-strategy":
                return DetectionStrategy
            case "x-mitre-matrix":
                return Matrix
            case "x-mitre-tactic":
                return Tactic
    except KeyError:
        raise Exception("Could match model with: \"" + model_type + "\"")