import lib.model
from lib.model import *
from lib.model.resource_manager import ResourceManager
from lib.model.collection import Collection
from neomodel import db, install_all_labels, config
from neomodel.exceptions import DoesNotExist
import json
from lib.commons import CustomPipelineKeys, clean_str
import time
import uuid as uuidLibrary
from datetime import datetime
from neomodel.properties import Property
import os

class Repository:
    _resource_manager_cache = {}
    
    remove_relationship_by_stix_uuid = """
    MATCH ()-[r]->()
    WHERE r.stix_uuid = $uuid
    DELETE r
    """
    
    def __init__(self):
        config.DATABASE_URL = os.getenv(
            "DATABASE_URL",
            "bolt://:@localhost:7687"   # fallback default for local dev
        )
        install_all_labels()
        self.cached_instances = {}
        self._instantiate_missing_resource_managers()
            
    def load_database(self, type_id_resource_mapping, domain):
        nodes_count, _ = db.cypher_query("MATCH (n) RETURN count(n)")
        rels_count, _ = db.cypher_query("MATCH ()-[r]->() RETURN count(r)")

        print(f"Nodes: {nodes_count[0][0]}, Relationships: {rels_count[0][0]}")
        
        relationship_queue = {}
        for matrix_uuid, matrix in type_id_resource_mapping["x-mitre-matrix"].items():
            print(matrix_uuid)
            # input("sanity check: ")
            for ref in matrix["tactic_refs"]:
                _, uuid1 = self._type_from_stix_uuid(matrix_uuid)
                _, uuid2 = self._type_from_stix_uuid(ref)
                derived_uuid = "relationship--" + str(uuidLibrary.uuid5(uuidLibrary.NAMESPACE_DNS, uuid1 + uuid2))
                
                relationship_queue[derived_uuid] = {
                    "stix_uuid": derived_uuid,
                    "source_ref": matrix_uuid,
                    "target_ref": ref,
                    "relationship_type": "contains",
                    CustomPipelineKeys.INT_MODIFIED: time.time(),
                    "modified": datetime.fromtimestamp(time.time())
                }
        self.add_tactic_technique_relationships(type_id_resource_mapping, relationship_queue)
        
        filtered_objects, relationship_queue_from_stix = self.filter_resources(type_id_resource_mapping, domain)
        relationship_queue.update(relationship_queue_from_stix)
        added_rels = len(relationship_queue)
        
        # temporary extraction of relationships
        with db.transaction: 
            for str_type, batch in filtered_objects.items():
                model_type = find_model_from_type(str_type)
                rm_for_batch = self._get_resource_manager(str_type)
                updated_mappin_for_batch = rm_for_batch.x_mitre_contents_serialized
                removal_queue = batch.pop("removed")
                
                self.perform_batch_operation(updated_mappin_for_batch, model_type, batch)
                for uuid in removal_queue:
                    object_domains = updated_mappin_for_batch[uuid]["domains"]
                    object_domains.remove(domain)
                    if len(object_domains) == 0:
                        self.cached_instances.pop(uuid, None)
                        model_type.nodes.get(stix_uuid=uuid).delete()
                        updated_mappin_for_batch.pop(uuid)
                    else:
                       self.remove_label_from_node(uuid, clean_str(domain))
                rm_for_batch.x_mitre_contents_serialized = updated_mappin_for_batch
                rm_for_batch.save()
            
            # connect nodes at the end
            added_rels = len(relationship_queue) - added_rels
            self.process_relationship_queue(relationship_queue, domain)
        nodes_count, _ = db.cypher_query("MATCH (n) RETURN count(n)")
        rels_count, _ = db.cypher_query("MATCH ()-[r]->() RETURN count(r)")
        print(f"Nodes: {nodes_count[0][0]}, Relationships: {rels_count[0][0]}")
        print(added_rels)
        # input("results: ")
    
    def add_tactic_technique_relationships(self, filtered_objects, relationship_queue):
        # resolve tactic names using tactic cache for tactic relationships
        tactic_name_cache = {}
        for tactic_uuid, tactic in filtered_objects["x-mitre-tactic"].items():
            tactic_name_cache[tactic["name"].lower()] = tactic_uuid
        added_rels = 0
        for technique_uuid, technique in filtered_objects["attack-pattern"].items():
            if "related_tactics" not in technique:
                continue
            for tactic_name in technique["related_tactics"]:
                # specific patch-fix
                tactic_name = tactic_name.replace("-", " ")
                
                # resolve name
                resolved_source_ref = None
                try:
                    resolved_source_ref = tactic_name_cache[tactic_name]
                except KeyError:
                    tactic_obj = Tactic.nodes.get(name=tactic_name)
                    resolved_source_ref = tactic_obj.stix_uuid
                    self.cached_instances[resolved_source_ref] = tactic_obj
                    print(tactic_name_cache)
                    print(tactic_name)
                    print(technique_uuid)
                    raise Exception("lowkey whattheufck")
                
                _, uuid1 = self._type_from_stix_uuid(technique_uuid)
                _, uuid2 = self._type_from_stix_uuid(resolved_source_ref)
                derived_uuid = "relationship--" + str(uuidLibrary.uuid5(uuidLibrary.NAMESPACE_DNS, uuid1 + uuid2))
        
                # add relationship queue
                relationship_queue[derived_uuid] = {
                    "stix_uuid": derived_uuid,
                    "source_ref": technique_uuid,
                    "target_ref": resolved_source_ref,
                    "relationship_type": "technique_of",
                    CustomPipelineKeys.INT_MODIFIED: time.time(),
                    "modified": datetime.fromtimestamp(time.time())
                }
                added_rels += 1
        print(added_rels)
        # input("found relationshisps")
    
    def process_relationship_queue(self, relationship_queue, domain):
        relation_updates, _ = self.filter_resources({"relationship": relationship_queue}, domain, False)
        relation_sorted_obj = relation_updates["relationship"]
        # filtered
        relation_removes = relation_sorted_obj.pop("removed")
        rm = self._get_resource_manager("relationship")
        updated_mappin_for_batch = rm.x_mitre_contents_serialized
        print("what is taking so long?")
        # process relationship queue
        for operation, relation_batch in relation_sorted_obj.items():
            for relation in relation_batch:
                source_ref = relation.pop("source_ref")
                target_ref = relation.pop("target_ref")
                int_modified = relation.pop(CustomPipelineKeys.INT_MODIFIED)
                
                #temprory ics checks
                try:
                    self._type_from_stix_uuid(source_ref)
                    self._type_from_stix_uuid(target_ref)
                except Exception:
                    continue
                
                source = self._load_model_from_stix_uuid(source_ref)
                target = self._load_model_from_stix_uuid(target_ref)
                relatinoship_type = relation.pop("relationship_type")
                # for stix relationship types
                relatinoship_type = relatinoship_type.replace("-", "_")
                if operation == "updated":
                    # need to redefine source / target
                    old_source_ref = updated_mappin_for_batch[relation["stix_uuid"]]["source_ref"]
                    old_target_ref = updated_mappin_for_batch[relation["stix_uuid"]]["target_ref"]
                    old_source = self._load_model_from_stix_uuid(old_source_ref)
                    old_target = self._load_model_from_stix_uuid(old_target_ref)
                    relation_obj = getattr(old_source, relatinoship_type).disconnect(old_target)
                    
                    updated_mappin_for_batch[relation["stix_uuid"]]["modified"] = int_modified
                    if domain not in updated_mappin_for_batch[relation["stix_uuid"]]["domains"]:
                        updated_mappin_for_batch[relation["stix_uuid"]]["domains"].append(domain)
                    updated_mappin_for_batch[relation["stix_uuid"]]["source_ref"] = source_ref
                    updated_mappin_for_batch[relation["stix_uuid"]]["target_ref"] = target_ref
                    # TODO: remove the label from the other node
                else:
                    updated_mappin_for_batch[relation["stix_uuid"]] = {
                        "modified": int_modified,
                        "domains": [domain],
                        "source_ref": source_ref,
                        "target_ref": target_ref
                    }
                
                getattr(source, relatinoship_type).connect(target, relation)
                if relation["stix_uuid"] == "relationship--cf99af2f-2e1b-5dea-9f96-d52b19e0f729":
                    # input("i found the weird model why update no work")
                    pass
                # TODO: Label the new target node
                
        for relation_uuid in relation_removes:
            db.cypher_query(self.remove_relationship_by_stix_uuid, {"uuid": relation_uuid})
            # relationship not scoped by domains
            updated_mappin_for_batch.pop(relation_uuid)
        # input("done with relation mapping")
        print("before_saving_serialized")
        rm.x_mitre_contents_serialized = updated_mappin_for_batch
        rm.save()
        print("after_saving_serialized")
                
    def _instantiate_json(self, operation, object_class, stix_uuid):
        object_instance = None
        if operation == "updated":
            object_instance = object_class.nodes.get(stix_uuid=stix_uuid)
        elif operation == "added":
            object_instance =  object_class()
        else:
            raise Exception("invalid operation")
        
        return object_instance, object_class
        
    def remove_label_from_node(self, stix_uuid, label_to_remove):
        query = f"""
        MATCH (n {{stix_uuid: $uuid}})
        REMOVE n:{label_to_remove}
        RETURN n
        """
        results, meta = db.cypher_query(query, {'uuid': stix_uuid})
        
    def perform_batch_operation(self, mappin_for_batch, model_type, operation_batch):
        for operation, operation_data in operation_batch.items():
            # add or update
            for obj_dict in operation_data:
                
                # assume whenever a stix object is modified, it's domains field are also maintained across all stix files
                #
                # ex: if you are parsing a specific enterprise-attack.json lets for resourceA, uuid=123, and
                # x_mitre_domains = ["enterprise-attack", "mobile-attack"], which means this resource will be in both
                # enterprise-attack.json and mobile-attack.json. If mobile-attack decides to remove it from it's domain,
                # resourceA in enterprise-attack.json will have it's x_mitre_domains field to be updated to be ["enterprise-attack"]
                #
                # note, this means, when parsing both: enterprise-attack.json and mobile-attack.json, the resource would only
                # be updated once.
                mappin_for_batch[obj_dict["stix_uuid"]] = {
                    "modified": obj_dict.pop(CustomPipelineKeys.INT_MODIFIED),
                    "domains": obj_dict["x_mitre_domains"]
                }
                obj_instance, obj_class = self._instantiate_json(operation, model_type, obj_dict["stix_uuid"])
                self._fill_model_with_dict(obj_instance, obj_dict)
                print(obj_dict)
                obj_instance.save()
                    
                # add any (new) custom labels to object
                # TODO: Clear labels if operation is updated
                parsed_labels = obj_dict.pop("mapipieline_added_labels")
                for label in parsed_labels:
                    if label not in obj_class.__optional_labels__:
                        raise Exception("unexpected label: " + label + " for class: " + str(obj_class))
                    db.cypher_query(f"MATCH (n:{obj_class.__name__}) WHERE id(n)={obj_instance.element_id.split(":")[-1]} SET n:{label}")

                self.cached_instances[obj_instance.stix_uuid] = obj_instance
        
    # returns bundles of objects that need change
    def filter_resources(self, resource_mapping, domain, exclude_relationships=True):
        formatted_resources = {}
        outputdict = {}
        excluded_relationships = []
        for type in resource_mapping:
            if type == "relationship" and exclude_relationships:
                excluded_relationships = resource_mapping["relationship"]
                continue
            resource_manager_map = self._get_resource_manager(type).x_mitre_contents_serialized
            mappings = resource_mapping[type]
            if type == "relationship":
                print("processing: " + str(len(mappings)))
                # input("waiting.....")
            filtered_resources = {
                "updated": [],
                "added": [],
                "removed": []
            }
            existing_resource_uuids = set(resource_manager_map)
            for uuid, obj_json in mappings.items():
                int_modified = obj_json[CustomPipelineKeys.INT_MODIFIED]
                
                if uuid not in resource_manager_map:
                    filtered_resources["added"].append(obj_json)
                    continue
                elif resource_manager_map[uuid]["modified"] < int_modified:
                    filtered_resources["updated"].append(obj_json)
                existing_resource_uuids.remove(uuid)
            for uuid in existing_resource_uuids:
                if domain in resource_manager_map[uuid]["domains"]:
                    filtered_resources["removed"].append(uuid)
            formatted_resources[type] = filtered_resources
            #debugging
            outputdict[type] = filtered_resources["removed"]
        if len(excluded_relationships) == 0:
            print(len(formatted_resources["relationship"]["removed"]))
            # input("bingo")
        return formatted_resources, excluded_relationships
    
    def _fill_model_with_dict(self, instantiatedModel, attribute_dict):
        for att_name, _ in type(instantiatedModel).__all_properties__:
            # standardize name
            if att_name == "name":
                attribute_dict[att_name] = attribute_dict[att_name].lower()
            try:
                setattr(instantiatedModel, att_name, attribute_dict[att_name])
            except KeyError:
                pass
    
    def _load_model_from_stix_uuid(self, uuid):
        try:
            return self.cached_instances[uuid]
        except KeyError:
            model, _ = self._type_from_stix_uuid(uuid)
            self.cached_instances[uuid] = model.nodes.get(stix_uuid=uuid)
            return self.cached_instances[uuid]
    def _type_from_stix_uuid(self, uuid):
        class_type, extracted_uuid = uuid.split("--")
        return find_model_from_type(class_type), extracted_uuid
    # ResourceManager
    def _instantiate_missing_resource_managers(self):
        with db.transaction: 
            models = set(map(lambda model_class: model_class.__name__, MODEL_LIST))
            for r in ResourceManager.nodes.all():
                models.remove(r.resource)
            
            for instantiate_models in models:
                r = ResourceManager(resource=instantiate_models)
                r.save()
                Repository._resource_manager_cache[instantiate_models] = r
                
    def _get_resource_manager(self, resource_type):
        model_name = find_model_from_type(resource_type).__name__
        if model_name in Repository._resource_manager_cache:
            return Repository._resource_manager_cache[model_name]
        extracted_rm =  ResourceManager.nodes.filter(resource=model_name).first()
        Repository._resource_manager_cache[model_name] = extracted_rm
        return extracted_rm