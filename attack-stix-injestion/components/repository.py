import lib.model
from lib.model import *
from neomodel import db, install_all_labels, config

import time

class Repository:
    SKIPPED = ["x-mitre-collection", "x-mitre-matrix", "marking-definition", "identity"]
    
    def __init__(self):
        config.DATABASE_URL = 'bolt://:@localhost:7687'  # default
        install_all_labels()
    
    def load_database(self, json_objects):
        print("started loading")
        self.cached_instances = {}
        queued_relationships = []
        with db.transaction: 
            for json_model_rep in json_objects:
                if json_model_rep["type"] in self.SKIPPED:
                    continue
                object_class = find_model_from_json(json_model_rep)
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