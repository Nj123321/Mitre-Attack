from .sub_technique import SubTechnique
from .technique import Technique
from .campaign import Campaign
from .mitigation import Mitigation
from .group import Group
from .relationship import RelationshipModel
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
    RelationshipModel,
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

def find_model_from_type(model_type):
    try:
        match model_type:
            # stix object data
            case "attack-pattern":
                return Technique
            case "sub-attack-pattern":
                return SubTechnique
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
                return RelationshipModel
            
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
        pass
    raise Exception("Could match model with: \"" + model_type + "\"")