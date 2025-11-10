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
            
            # to associate technique with tactics, have to build custom relationships
            tactic_cache = {}
            technique_tactic_relationships = []
            
            for operation, object_arr in  filtered_objects.items():
                # remove
                if operation == "removed":
                    if user_input == "skip":
                        continue
                    for uuid in object_arr:
                        model_type, _ = self._type_from_stix_uuid(uuid, True)
                        model_type.nodes.get(stix_uuid=uuid).delete()
                    continue
                
                # add or update
                for obj_dict in object_arr:
                    # skip bad objects
                    if obj_dict["type"] in self.SKIPPED:
                        print("SKIPPED")
                        continue
                    # skip relationships for later
                    if operation == "added" and obj_dict["type"] == "relationship":
                        relationship_queue.append(obj_dict)
                        continue
                    # decorate json obj
                    if obj_dict["type"] == "attack-pattern":
                        try:
                            obj_dict["x_mitre_is_subtechnique"]
                        except KeyError:
                            obj_dict["x_mitre_is_subtechnique"] = False
                    
                    obj_instance, obj_class = self._instantiate_json(operation, obj_dict)
                    self._fill_model_with_dict(obj_instance, obj_dict)
                    obj_instance.save()
                    
                    if obj_class is Matrix:
                        for ref in obj_dict["tactic_refs"]:
                            relationship_queue.append({
                                "source_ref": obj_instance.stix_uuid,
                                "target_ref": ref,
                                "relationship_type": "contains"
                            })
                    if obj_class is Tactic:
                        # print("putting " + obj_instance.name + " into tactic cache")
                        # user_input = input("Enter something: ")
                        tactic_cache[obj_instance.name] = obj_instance.stix_uuid
                    if obj_class is Technique:
                        for tactic in obj_dict["related_tactics"]:
                            tactic = tactic.lower().replace("-", " ")
                            technique_tactic_relationships.append({
                                "source_ref": obj_instance.stix_uuid,
                                "target_tactic_name": tactic,
                                "relationship_type": "technique_of"
                            })
                    
                    # add any (new) custom labels to object
                    # TODO: Clear labels if operation is updated
                    parsed_labels = obj_dict.pop("mapipieline_added_labels")
                    for label in parsed_labels:
                        if label not in getattr(obj_instance, "__optional_labels__"):
                            print(getattr(obj_instance, "__optional_labels__"))
                            raise Exception("unexpected label: " + label + " for class: " + str(obj_class))
                        db.cypher_query(f"MATCH (n:{obj_class.__name__}) WHERE id(n)={obj_instance.element_id.split(":")[-1]} SET n:{label}")

                    self.cached_instances[obj_instance.stix_uuid] = obj_instance
                
                # resolve tactic names using tactic cache for tactic relationships
                for tactic_to_technique in technique_tactic_relationships:
                    resolved_source_ref = None
                    tactic_name = tactic_to_technique.pop("target_tactic_name")
                    try:
                        resolved_source_ref = tactic_cache[tactic_name]
                    except KeyError:
                        tactic = Tactic.nodes.get(name=tactic_name)
                        resolved_source_ref = tactic.stix_uuid
                        # add to cache for relationship
                        self.cached_instances[resolved_source_ref] = tactic
                    tactic_to_technique["target_ref"] = resolved_source_ref
                    relationship_queue.append(tactic_to_technique)
                
                # process relationship queue
                for relation in relationship_queue:
                    print(relation)
                    source_ref = relation.pop("source_ref")
                    target_ref = relation.pop("target_ref")
                    
                    source = self._load_model_from_stix_uuid(source_ref)
                    target = self._load_model_from_stix_uuid(target_ref)
                    relatinoship_type = relation.pop("relationship_type")
                    # for stix relationship types
                    relatinoship_type = relatinoship_type.replace("-", "_")
                    
                    # if there is remaining metadata or a custom relationship
                    if relation:
                        getattr(source, relatinoship_type).connect(target, relation)
                    else:
                        getattr(source, relatinoship_type).connect(target)
                
        
    # returns bundles of objects that need change
    def filter_resources(self, resource_mapping):
        filtered_resources = {}
        filtered_resources["updated"] = []
        filtered_resources["removed"] = []
        filtered_resources["added"] = []
        
        mitre_collection = resource_mapping.pop("current-collection_being_loaded")
        current_id_to_modified = mitre_collection.pop("x_mitre_contents_dictionized")
        try:
            existing_collection = Collection.nodes.first()
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
            # standardize name
            if att_name == "name":
                attribute_dict[att_name] = attribute_dict[att_name].lower()
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