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
        self._instantiate_missing_resource_managers()
            
    def load_database(self, type_id_resource_mapping, domain):
        nodes_count, _ = db.cypher_query("MATCH (n) RETURN count(n)")
        rels_count, _ = db.cypher_query("MATCH ()-[r]->() RETURN count(r)")

        print(f"Nodes: {nodes_count[0][0]}, Relationships: {rels_count[0][0]}")
        filtered_objects = self.filter_resources(type_id_resource_mapping, domain)
        
        # caches to help resolve relationships references, neccessary / optimization
        relationship_queue = filtered_objects['relationship'].pop("added")
        
        # temporary extraction of relationships
        for op, matrix_batch in filtered_objects["x-mitre-matrix"].items():
            if op != "removed":
                for matrix in matrix_batch:
                    for ref in matrix["tactic_refs"]:
                        relationship_queue.append({
                            "source_ref": matrix["stix_uuid"],
                            "target_ref": ref,
                            "relationship_type": "contains"
                        })
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
                        model_type.nodes.get(stix_uuid=uuid).delete()
                        updated_mappin_for_batch.pop(uuid)
                    else:
                       self.remove_label_from_node(uuid, clean_str(domain))
                rm_for_batch.x_mitre_contents_serialized = updated_mappin_for_batch
                rm_for_batch.save()
            
            
            # connect nodes at the end
            self.add_tactic_technique_relationships(filtered_objects, relationship_queue)
            self.process_relationship_queue(relationship_queue)
        nodes_count, _ = db.cypher_query("MATCH (n) RETURN count(n)")
        rels_count, _ = db.cypher_query("MATCH ()-[r]->() RETURN count(r)")
        print(f"Nodes: {nodes_count[0][0]}, Relationships: {rels_count[0][0]}")
        # input("results: ")
    
    def add_tactic_technique_relationships(self, filtered_objects, relationship_queue):
        # resolve tactic names using tactic cache for tactic relationships
        tactic_name_cache = {}
        for op, tactic_batch in filtered_objects["x-mitre-tactic"].items():
            for tactic in tactic_batch:
                tactic_name_cache[tactic["name"]] = tactic["stix_uuid"]
        for op, technique_batch in filtered_objects["attack-pattern"].items():
            for technique in technique_batch:
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
            
                    # add relationship queue
                    relationship_queue.append({
                        "source_ref": technique["stix_uuid"],
                        "target_ref": resolved_source_ref,
                        "relationship_type": "technique_of"
                    })
    
    def process_relationship_queue(self, relationship_queue):
        # process relationship queue
        for relation in relationship_queue:
            source_ref = relation.pop("source_ref")
            target_ref = relation.pop("target_ref")
            
            #temprory ics checks
            try:
                self._type_from_stix_uuid(source_ref)
                self._type_from_stix_uuid(target_ref)
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
    def filter_resources(self, resource_mapping, domain):
        formatted_resources = {}
        outputdict = {}
        for type in resource_mapping:
            resource_manager_map = self._get_resource_manager(type).x_mitre_contents_serialized
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
        # input("removal for " + domain + ": ")
        return formatted_resources
    
    def _fill_model_with_dict(self, instantiatedModel, attribute_dict):
        for att_name, _ in type(instantiatedModel).__all_properties__:
            # standardize name
            if att_name == "name":
                attribute_dict[att_name] = attribute_dict[att_name].lower()
            setattr(instantiatedModel, att_name, attribute_dict[att_name])
    
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