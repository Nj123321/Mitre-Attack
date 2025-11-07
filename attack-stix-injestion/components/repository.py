import model
from model import *
from neomodel import db

import time

class Repository:
    SKIPPED = ["x-mitre-collection", "x-mitre-matrix", "marking-definition", "identity"]
    
    def __init__(self):
        model.init_models()
    
    def load_database(self, json_objects):
        print("started loading")
        self.cached_instances = {}
        queued_relationships = []
        with db.transaction: 
            for json_model_rep in json_objects:
                object_class = self.find_model(json_model_rep)
                if object_class is None:
                    continue
                if object_class is Relationship:
                    r = {}
                    # for att_name, _ in Relationship.__all_properties__:
                        # r[att_name] = json_model_rep[att_name]
                    # r["source_ref"] = json_model_rep["source_ref"]
                    # r["target_ref"] = json_model_rep["target_ref"]
                    # r["relationship_type"] = json_model_rep["relationship_type"]
                    queued_relationships.append(json_model_rep)
                    continue
                instantiatedModel = object_class()
                print("whack: " + object_class.__name__)
                for att_name, _ in object_class.__all_properties__:
                    print("attribute: " + att_name)
                    setattr(instantiatedModel, att_name, json_model_rep[att_name])
            
                instantiatedModel.save()
                for label in json_model_rep["mapipieline_added_labels"]:
                    db.cypher_query(f"MATCH (n:{object_class.__name__}) WHERE id(n)={instantiatedModel.element_id.split(":")[-1]} SET n:{label}")
                    # instantiatedModel.add_label(label)
                if instantiatedModel.attack_uuid == "malware--6a21e3a4-5ffe-4581-af9a-6a54c7536f44":
                    print("type+ " + str(type(instantiatedModel.attack_uuid)))
                    print("chaching: " + instantiatedModel.attack_uuid)
                self.cached_instances[instantiatedModel.attack_uuid] = instantiatedModel
            for relation in queued_relationships:
                source_ref = relation.pop("source_ref")
                target_ref = relation.pop("target_ref")
                
                source = self.cached_instances[source_ref]
                target = self.cached_instances[target_ref]
                print(relation)
                print("relatinoid: " + relation["attack_uuid"])
                match relation["relationship_type"]:
                    case "uses":
                        source.uses.connect(target, relation)
                    case "mitigates":
                        source.mitigates.connect(target, relation)
                    case "subtechnique-of":
                        source.subtechnique_of.connect(target, relation)
                    case "detects":
                        source.detects.connect(target, relation)
                    case "attributed-to":
                        source.attributed_to.connect(target, relation)
                    case "targets":
                        source.targets.connect(target, relation)
                    case "revoked-by":
                        source.revoked_by.connect(target, relation)
        print("finsihed loading")
            # for relationships in queued_relationships:
                
    def find_model(self, model):
        model_type = model["type"]
        match model_type:
            # stix object data
            case "attack-pattern":
                if model["x_mitre_is_subtechnique"] == True:
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
            # case "x-mitre-collection":
                # return Collection()
            case "x-mitre-data-component":
                return DataComponent
            case "x-mitre-data-source":
                return DataSource
            case "x-mitre-detection-strategy":
                return DetectionStrategy
            # case "x-mitre-matrix":
                # return Matrix()
            case "x-mitre-tactic":
                return Tactic
        if model_type in self.SKIPPED:
            return
        raise Exception("Could match model with: " + model_type)