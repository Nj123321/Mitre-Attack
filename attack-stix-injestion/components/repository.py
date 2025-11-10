import lib.model
from lib.model import *
from lib.model.collection import Collection
from neomodel import db, install_all_labels, config
from neomodel.exceptions import DoesNotExist
import json

class Repository:
    SKIPPED = ["marking-definition", "identity"]
    
    def __init__(self):
        config.DATABASE_URL = 'bolt://:@localhost:7687'  # default
        install_all_labels()
        self.cached_instances = {}
        
    def _instantiate_json(self, operation, json_obj):
        object_instance = None
        object_class = find_model_from_json(json_obj)
        if object_class is None:
            raise Exception("cannot match model: " +  json_obj["type"])
        if operation == "updated":
            object_instance = object_class.nodes.get(stix_uuid=json_obj["stix_uuid"])
        elif operation == "added":
            object_instance =  object_class()
        else:
            raise Exception("invalid operation")
        
        return object_instance, object_class
            
    
    def load_database(self, id_resource_mapping):
        # custom id defined by parser
        with db.transaction: 
            filtered_objects = self.filter_resources(id_resource_mapping)

            # user confirmation
            print(filtered_objects["updated"][:10])
            user_input = input("Updated: ")
            print(filtered_objects["added"][:10])
            user_input = input("added: ")
            print(list(filtered_objects["removed"])[:10])
            user_input = input("removed: ")
            
            # save relationships last, we have in-memory caches no need to load
            # nodes if we've updated them before
            relationship_queue = []
            
            for operation, object_arr in  filtered_objects.items():
                if operation == "removed":
                    for uuid in object_arr:
                        model_type, _ = self._type_from_stix_uuid(uuid, True)
                        model_type.nodes.get(stix_uuid=uuid).delete()
                    continue
                
                # add or update
                for obj in object_arr:
                    # skip bad objects
                    if obj["type"] in self.SKIPPED:
                        print("SKIPPED")
                        continue
                    # skip relationships for later
                    if operation == "added" and obj["type"] == "relationship":
                        relationship_queue.append(obj)
                        continue
                    # decorate json obj
                    if obj["type"] == "attack-pattern":
                        try:
                            obj["x_mitre_is_subtechnique"]
                        except KeyError:
                            obj["x_mitre_is_subtechnique"] = False
                    
                    obj_instance, obj_class = self._instantiate_json(operation, obj)
                    self._fill_model_with_dict(obj_instance, obj)
                    obj_instance.save()
                    
                    # add any (new) custom labels to object
                    # TODO: Clear labels if operation is updated
                    parsed_labels = obj.pop("mapipieline_added_labels")
                    for label in parsed_labels:
                        if label not in getattr(obj_instance, "__optional_labels__"):
                            raise Exception("unexpected label: " + label + " for class: " + str(obj_class))
                        db.cypher_query(f"MATCH (n:{obj_class.__name__}) WHERE id(n)={obj_instance.element_id.split(":")[-1]} SET n:{label}")

                    self.cached_instances[obj_instance.stix_uuid] = obj_instance
                
                # process relationship queue
                for relation in relationship_queue:
                    source_ref = relation.pop("source_ref")
                    target_ref = relation.pop("target_ref")
                    
                    source = self._load_model_from_stix_uuid(source_ref)
                    target = self._load_model_from_stix_uuid(target_ref)
                    print(relation)
                    print("relatinoid: " + relation["stix_uuid"])
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
                
        
    # returns bundles of objects that need change
    def filter_resources(self, resource_mapping):
        filtered_resources = {}
        filtered_resources["updated"] = []
        filtered_resources["removed"] = []
        filtered_resources["added"] = []
        
        mitre_collection = resource_mapping.pop("current-collection_being_loaded")
        current_id_to_modified = mitre_collection.pop("x_mitre_contents_dictionized")
        try:
            existing_collection = Collection.nodes.get(stix_uuid=mitre_collection["stix_uuid"])
            exisiting_id_to_modified = existing_collection.x_mitre_contents_serialized
            
            existing_resources = set(exisiting_id_to_modified.keys())
            for stix_id in current_id_to_modified.keys():
                try:
                    if current_id_to_modified[stix_id] > exisiting_id_to_modified[stix_id]:
                        filtered_resources["updated"].append(resource_mapping.pop(stix_id))
                    existing_resources.remove(stix_id)
                    resource_mapping.pop(stix_id)
                except KeyError:
                    pass # new resources, to be added later on
            filtered_resources["removed"] = existing_resources
            
            mitre_collection["x_mitre_contents_serialized"] = current_id_to_modified
            self._fill_model_with_dict(existing_collection, mitre_collection)
            existing_collection.save()
        except DoesNotExist:
            mitre_collection["x_mitre_contents_serialized"] = current_id_to_modified
            filtered_resources["added"].append(mitre_collection)
            pass
        
        for id, object in resource_mapping.items():
            # print("adding id: " + id)
            # user_input = input("added: ")
            filtered_resources["added"].append(object)
        return filtered_resources
    
    def _fill_model_with_dict(self, instantiatedModel, attribute_dict):
        for att_name, _ in type(instantiatedModel).__all_properties__:
            setattr(instantiatedModel, att_name, attribute_dict[att_name])
    
    def _type_from_stix_uuid(self, uuid, deleted=False):
        class_type, uuid = uuid.split("--")
        mock_json = {"type" : class_type}
        return find_model_from_json(mock_json, deleted), uuid
    
    def _load_model_from_stix_uuid(self, uuid):
        try:
            return self.cached_instances[uuid]
        except KeyError:
            model, _ = self._type_from_stix_uuid(uuid, True)
            self.cached_instances[uuid] = model.nodes.get(stix_uuid=uuid)
            return self.cached_instances[uuid]