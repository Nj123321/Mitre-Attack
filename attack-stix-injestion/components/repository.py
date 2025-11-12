import lib.model
from lib.model import *
from lib.model.resource_manager import ResourceManager
from lib.model.collection import Collection
from neomodel import db, install_all_labels, config
from neomodel.exceptions import DoesNotExist
import json
from lib.commons import CustomPipelineKeys, clean_str

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
    def load_database(self, type_id_resource_mapping, domain):
        nodes_count, _ = db.cypher_query("MATCH (n) RETURN count(n)")
        rels_count, _ = db.cypher_query("MATCH ()-[r]->() RETURN count(r)")

        print(f"Nodes: {nodes_count[0][0]}, Relationships: {rels_count[0][0]}")
        filtered_objects = self.filter_resources(type_id_resource_mapping, domain)
        # custom id defined by parser
        with db.transaction: 
            # caches to help resolve relationships references, neccessary / optimization
            relationship_queue = filtered_objects['relationship'].pop("added")
            tactic_cache = {}
            technique_tactic_relationships = []
            
            for str_type, batch in filtered_objects.items():
                self.perform_batch_operation(str_type, batch, domain, tactic_cache, relationship_queue, technique_tactic_relationships)
            
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
                
            # connect nodes at the end
            self.process_relationship_queue(relationship_queue)
        nodes_count, _ = db.cypher_query("MATCH (n) RETURN count(n)")
        rels_count, _ = db.cypher_query("MATCH ()-[r]->() RETURN count(r)")
        print(f"Nodes: {nodes_count[0][0]}, Relationships: {rels_count[0][0]}")
        # input("results: ")
    
    def process_relationship_queue(self, relationship_queue):
        # process relationship queue
        for relation in relationship_queue:
            source_ref = relation.pop("source_ref")
            target_ref = relation.pop("target_ref")
            
            #temprory ics checks
            try:
                Repository.type_from_stix_uuid(source_ref)
                Repository.type_from_stix_uuid(target_ref)
            except Exception:
                continue
            
            print(relation)
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
        
    def perform_batch_operation(self, str_type, operation_batch, domain, tactic_cache, relationship_queue, technique_tactic_relationships):
        model_type = find_model_from_type(str_type)
        rm_for_batch = self.get_resource_manager(str_type)
        mappin_for_batch = rm_for_batch.x_mitre_contents_serialized
        for operation, operation_data in operation_batch.items():
            if operation == "removed":
                for uuid in operation_data:
                    object_domains = mappin_for_batch[uuid]["domains"]
                    object_domains.remove(domain)
                    if len(object_domains) == 0:
                        model_type.nodes.get(stix_uuid=uuid).delete()
                        mappin_for_batch.pop(uuid)
                    else:
                       self.remove_label_from_node(uuid, clean_str(domain))
                continue
            
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
                if obj_class is Technique and "related_tactics" in obj_dict:
                    for tactic in obj_dict["related_tactics"]:
                        # specific patch-fix
                        tactic = tactic.replace("-", " ")
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
                
    def get_resource_manager(self, resource_type):
        model_name = find_model_from_type(resource_type).__name__
        if model_name in Repository._resource_manager_cache:
            return Repository._resource_manager_cache[model_name]
        extracted_rm =  ResourceManager.nodes.filter(resource=model_name).first()
        Repository._resource_manager_cache[model_name] = extracted_rm
        return extracted_rm
        
    # returns bundles of objects that need change
    def filter_resources(self, resource_mapping, domain):
        formatted_resources = {}
        outputdict = {}
        for type in resource_mapping:
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
            for uuid in existing_resource_uuids:
                if domain in resource_manager_map[uuid]["domains"]:
                    filtered_resources["removed"].append(uuid)
            formatted_resources[type] = filtered_resources
            #debugging
            outputdict[type] = filtered_resources["removed"]
        print(outputdict)
        input("removal for " + domain + ": ")
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