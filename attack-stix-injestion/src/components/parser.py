# handles json logic / field extraction / labels
# takes in hashes as inputs

# stores filters? as jsons? if time? parse based on jsons / transfomrs jsons 
# dyanmcailly creates filters based on class name -> file mapping
import json
import os
from mitre_common.commons import clean_str, extract_from_json, CustomPipelineKeys
from datetime import datetime, timezone

from .repository import Repository

# creates id -> object mapping, for faster lookup in repository layer
# also handles trasnfomations / labels / validation
class Parser:
    MAPPING_BASE = "resources/mappings/"
    IGNORED_VALUES = [
            "marking-definition", 
            "x-mitre-collection", 
            "identity",
            "x-mitre-asset"
        ]
    
    def __init__(self):
        self.mapping_cache = {}
    
    """
    Given list of json objects, transform each based on obj["type"] so that:
    {
        obj_type: {
            obj_id : obj_json,
            obj_id_2 : obj_json_2,
            ....
        }
        obj_type_v2:{
            ....
        }
        ....
    }
    """
    def parse_data(self, json_objects, domain):
        self.domain = domain
        formatted_resources = {}
        for obj in json_objects:
            if obj["type"] in Parser.IGNORED_VALUES:
                continue
            
            # transform object
            self._add_required_meta_data_fields(obj)
            self._derive_attributes(obj)
            self._add_labels(obj)
            self._transform_fields(obj)
            
            extracted_type = obj.pop(CustomPipelineKeys.EXTRACTED_TYPE)
            formatted_resources.setdefault(extracted_type, {})
            if obj["stix_uuid"] in formatted_resources[extracted_type]:
                raise Exception("dupicliate ids not alllowed: " + formatted_resources["id"])
            formatted_resources[extracted_type][obj["stix_uuid"]] = obj
        return formatted_resources
    
    def _derive_attributes(self, json_obj):
        mapping = self.load_mapping_cache(json_obj["type"])
        for att_name, att_path in mapping["derived_attributes"].items():
            search_path, required = self._filter_query_path(att_path)
            extracted = extract_from_json(json_obj, search_path, required)
            json_obj[att_name] = extracted
        
    # specific mitre / pipeline things
    def _add_required_meta_data_fields(self, json_obj):
        # adds model type for repository
        # custom for our case, keeping technique and subtechnique seperate
        # to divide ResourceManager
        # decoreate sub-technique
        model_type = json_obj["type"]
        if "x_mitre_is_subtechnique" in json_obj and json_obj["x_mitre_is_subtechnique"]:
            model_type = "sub-attack-pattern"
        json_obj[CustomPipelineKeys.EXTRACTED_TYPE] = model_type
        
        # used in ResourceManager, store floats rather than string timestamps
        time_stamp = json_obj["modified"]
        int_timestamp = -1
        if isinstance(time_stamp, str):
            time_stamp = datetime.strptime(time_stamp, "%Y-%m-%dT%H:%M:%S.%fZ")
            int_timestamp =  time_stamp.replace(tzinfo=timezone.utc).timestamp()
        else:
            int_timestamp =  time_stamp.timestamp()
        json_obj[CustomPipelineKeys.INT_MODIFIED] = int_timestamp
        
            
    # extract out keys, etc, transfomration, not changing keys just restructuring
    def _transform_fields(self, json_obj):
        attributes_mapping = self.load_mapping_cache(json_obj["type"])["attributes"]
        new_json = {}
        # greedily match mappings
        for key in attributes_mapping:
            search_path, required = self._filter_query_path(attributes_mapping[key])
            extracted = extract_from_json(json_obj, search_path, required, True)
            if extracted:
                new_json[key] = extracted
        new_json["mapipieline_added_labels"] = json_obj.pop("mapipieline_added_labels")
        if json_obj:
            pass
            # raise Exception(obj_type + " why is this not empty: " + str(json_obj))
        
        # put back the data
        for k, v in new_json.items():
            json_obj[k] = v

    # extracts and stores custom labels in "mapipieline_added_labels"
    def _add_labels(self, obj):
        labels = set()
        mapping = self.load_mapping_cache(obj["type"])
        for label_path in mapping["derived_labels"]:
            search_path, required = self._filter_query_path(label_path)
            extracted_labels = extract_from_json(obj, search_path, required)
            if extracted_labels:
                if not isinstance(extracted_labels, list):
                    extracted_labels = [extracted_labels]
                for label in extracted_labels:
                    label = clean_str(label)
                    labels.add(label)
        obj["mapipieline_added_labels"] = labels
        
    def _filter_query_path(self, path):
        required = False
        if path[-1] == "!":
            required = True
            path = path[:-1]
        return path, required

    # lazily loads in mappings
    def load_mapping_cache(self, resource_type):
        if resource_type in self.mapping_cache:
            return self.mapping_cache[resource_type]
        
        filepath = os.path.join(self.MAPPING_BASE, self.domain, resource_type + ".json")
        if not os.path.isfile(filepath):
            raise Exception("Could not find mappings for: " + resource_type)
        with open(filepath, "r") as f:
            self.mapping_cache[resource_type] = json.load(f)
        return self.mapping_cache[resource_type]