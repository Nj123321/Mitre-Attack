import lib.model
from lib.model import *
from lib.model.resource_manager import ResourceManager
from lib.model.collection import Collection
from neomodel import db, install_all_labels, config
from neomodel.exceptions import DoesNotExist
import json
from lib.commons import CustomPipelineKeys

class Repository:
    _resource_manager_cache = {}
    
    def __init__(self):
        config.DATABASE_URL = 'bolt://:@localhost:7687'  # default
        install_all_labels()
        self.cached_instances = {}
        
        # enusre resource_manager exists for all classes
        with db.transaction: 
            models = set(map(lambda model_class: model_class.__name__, MODEL_LIST))
            for r in ResourceManager.nodes.all():
                models.remove(r.resource)
            
            for instantiate_models in models:
                r = ResourceManager(resource=instantiate_models)
                r.save()
                Repository._resource_manager_cache[instantiate_models] = r
        
    def _instantiate_json(self, operation, object_class, stix_uuid):
        object_instance = None
        if operation == "updated":
            object_instance = object_class.nodes.get(stix_uuid=stix_uuid)
        elif operation == "added":
            object_instance =  object_class()
        else:
            raise Exception("invalid operation")
        
        return object_instance, object_class
        
    def perform_batch_operation(self, horrific_parameter, operation_batch, model_type, tactic_cache, relationship_queue, technique_tactic_relationships):
        rm_for_batch = self.get_resource_manager(horrific_parameter)
        mappin_for_batch = rm_for_batch.x_mitre_contents_serialized
        for operation, object_arr in operation_batch.items():
            # remove
            if operation == "removed":
                # for uuid in object_arr:
                    # model_type.nodes.get(stix_uuid=uuid).delete()
                continue
            
            # add or update
            for obj_dict in object_arr:
                modified_int = obj_dict.pop(CustomPipelineKeys.INT_MODIFIED)
                mappin_for_batch[obj_dict["stix_uuid"]] = {
                    "modified": modified_int,
                    "domains": obj_dict["x_mitre_domains"]
                }
                obj_instance, obj_class = self._instantiate_json(operation, model_type, obj_dict["stix_uuid"])
                self._fill_model_with_dict(obj_instance, obj_dict)
                obj_instance.save()
                if obj_class is Tactic:
                    tactic_cache[obj_instance.name] = obj_instance.stix_uuid
                if obj_class is Matrix:
                    for ref in obj_dict["tactic_refs"]:
                        relationship_queue.append({
                            "source_ref": obj_instance.stix_uuid,
                            "target_ref": ref,
                            "relationship_type": "contains"
                        })
                if obj_class is Technique:
                    if "related_tactics" not in obj_dict:
                        continue
                    tactics = obj_dict["related_tactics"]
                    if len(tactics) == 0:
                        raise Exception("fuckingweird")
                    for tactic in tactics:
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
                    if label not in obj_class.__optional_labels__:
                        raise Exception("unexpected label: " + label + " for class: " + str(obj_class))
                    db.cypher_query(f"MATCH (n:{obj_class.__name__}) WHERE id(n)={obj_instance.element_id.split(":")[-1]} SET n:{label}")

                self.cached_instances[obj_instance.stix_uuid] = obj_instance
        rm_for_batch.x_mitre_contents_serialized = mappin_for_batch
        rm_for_batch.save()
    
    def load_database(self, type_id_resource_mapping, domain):
        nodes_count, _ = db.cypher_query("MATCH (n) RETURN count(n)")
        rels_count, _ = db.cypher_query("MATCH ()-[r]->() RETURN count(r)")

        print(f"Nodes: {nodes_count[0][0]}, Relationships: {rels_count[0][0]}")
        input("loading domain: " + domain)
        filtered_objects = self.filter_resources(type_id_resource_mapping, domain)
        # custom id defined by parser
        with db.transaction: 
            # save relationships last, we have in-memory caches no need to load
            # nodes if we've updated them before
            relationship_queue = filtered_objects['relationship'].pop("added")
            
            # to associate technique with tactics, have to build custom relationships
            tactic_cache = {}
            technique_tactic_relationships = []
            
            for str_type, batch in filtered_objects.items():
                self.perform_batch_operation(str_type, batch, find_model_from_type(str_type), tactic_cache, relationship_queue, technique_tactic_relationships)
            
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
                
                #temprory ics checks
                try:
                    Repository.type_from_stix_uuid(source_ref)
                    Repository.type_from_stix_uuid(target_ref)
                except Exception:
                    continue
                
                source = self._load_model_from_stix_uuid(source_ref)
                target = self._load_model_from_stix_uuid(target_ref)
                relatinoship_type = relation.pop("relationship_type")
                # for stix relationship types
                relatinoship_type = relatinoship_type.replace("-", "_")
                
                # if there is remaining metadata or a custom relationship
                if relation:
                    print("===================================")
                    print(relation)
                    getattr(source, relatinoship_type).connect(target, relation)
                else:
                    getattr(source, relatinoship_type).connect(target)
        print(f"Nodes: {nodes_count[0][0]}, Relationships: {rels_count[0][0]}")
        input("results: ")
                
    def get_resource_manager(self, resource_type):
        print(resource_type)
        model_name = find_model_from_type(resource_type).__name__
        if model_name in Repository._resource_manager_cache:
            return Repository._resource_manager_cache[model_name]
        extracted_rm =  ResourceManager.nodes.filter(resource=model_name).first()
        Repository._resource_manager_cache[model_name] = extracted_rm
        return extracted_rm
        
    # returns bundles of objects that need change
    def filter_resources(self, resource_mapping, domain):
        formatted_resources = {}
        for type in resource_mapping:
            print("processing " + type + " ==========================================")
            resource_manager_map = self.get_resource_manager(type).x_mitre_contents_serialized
            mappings = resource_mapping[type]
            filtered_resources = {
                "updated": [],
                "added": [],
                "removed": []
            }
            existing_resource_uuids = set(resource_manager_map)
            for uuid, obj_json in mappings.items():
                # patch-fix
                int_modified = obj_json[CustomPipelineKeys.INT_MODIFIED]
                if type == "relationship":
                    obj_json.pop(CustomPipelineKeys.INT_MODIFIED)
                
                if uuid not in resource_manager_map:
                    filtered_resources["added"].append(obj_json)
                    continue
                elif resource_manager_map[uuid]["modified"] < int_modified:
                    filtered_resources["updated"].append(obj_json)
                existing_resource_uuids.remove(uuid)
            filtered_resources["removed"] = existing_resource_uuids
            formatted_resources[type] = filtered_resources
            if type == "relationship":
                print(filtered_resources["added"][:4])
                input("Added")
                print(filtered_resources["updated"][:4])
                input("updated")
                print(filtered_resources["removed"])
                input("removed")
        print("finallydone==========================================")
        return formatted_resources
    
    def _fill_model_with_dict(self, instantiatedModel, attribute_dict):
        for att_name, _ in type(instantiatedModel).__all_properties__:
            # standardize name
            if att_name == "name":
                attribute_dict[att_name] = attribute_dict[att_name].lower()
            setattr(instantiatedModel, att_name, attribute_dict[att_name])
    
    @classmethod
    def type_from_stix_uuid(clz, uuid):
        class_type, extracted_uuid = uuid.split("--")
        return find_model_from_type(class_type), extracted_uuid
    
    def _load_model_from_stix_uuid(self, uuid):
        try:
            return self.cached_instances[uuid]
        except KeyError:
            model, _ = Repository.type_from_stix_uuid(uuid)
            self.cached_instances[uuid] = model.nodes.get(stix_uuid=uuid)
            return self.cached_instances[uuid]