# handles json logic / field extraction / labels
# takes in hashes as inputs

# stores filters? as jsons? if time? parse based on jsons / transfomrs jsons 
# dyanmcailly creates filters based on class name -> file mapping
import json
import os
import lib.constants
from datetime import datetime, timezone

from .repository import Repository

# creates id -> object mapping, for faster lookup in repository layer
# also handles trasnfomations / labels / validation
class Parser:
    REMOVED_VALUES = ["object_marking_refs"]
    MAPPING_BASE = "resources/mappings/"
    IGNORED_VALUES = [
            "marking-definition", 
            "x-mitre-collection", 
            "identity",
            "x-mitre-asset"
        ]
    
    def __init__(self):
        self.mapping_cache = {}
        print("initilaizing parser")
    
    """
    Given list of json objects, transform each so that:
    {
        obj_type: {
            obj_id : obj_json
            ....
        }
        ....
    }
    """
    def parse_data(self, json_objects, domain):
        self.domain = domain
        formatted_resources = {}
        for obj in json_objects:
            extracted_type = obj["type"]
            if extracted_type in Parser.IGNORED_VALUES:
                continue
            self._derive_attributes(obj)
            self._add_labels(obj)
            self._transform_fields(obj)
            self._remove_common_fields(obj)
            
            formatted_resources.setdefault(obj["type"], {})
            # TODO: move to validation function
            # re-extract type, type changed for subtechnique - fix
            if obj["stix_uuid"] in formatted_resources[obj["type"]]:
                raise Exception("dupicliate ids not alllowed: " + formatted_resources["id"])
            print(obj["stix_uuid"])
            obj["int_modified"] = self.extract_modified(obj["modified"])
            formatted_resources[obj["type"]][obj["stix_uuid"]] = obj
        return formatted_resources
    
    def extract_modified(self, time_stamp):
        if isinstance(time_stamp, str):
            time_stamp = datetime.strptime(time_stamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            return time_stamp.timestamp()
        return time_stamp.replace(tzinfo=timezone.utc).timestamp()
    
    def _derive_attributes(self, json_obj):
        mapping = self.load_mapping_cache(json_obj["type"])
        for att_name, att_path in mapping["derived_attributes"].items():
            extracted = self._extract(json_obj, att_path)
            json_obj[att_name] = extracted
        
        # custom for our case, keeping technique and subtechnique seperate
        # to divide ResourceManager
        # decoreate sub-technique
        try:
            if json_obj["type"] == "attack-pattern" and json_obj["x_mitre_is_subtechnique"] == True:
                json_obj["type"] = "sub-attack-pattern"
                # json_obj["id"] = "sub-" + json_obj["id"]
        except KeyError:
            pass
            
    # extract out keys, etc, transfomration, not changing keys just restructuring
    def _transform_fields(self, json_obj):
        obj_type = json_obj["type"]
        mapping = self.load_mapping_cache(obj_type)
        new_json = {}
        for key in mapping["attributes"]:
            # greedily match mappings
            path = mapping["attributes"][key]
            split_path = path.split("@", 1)
            search_path = split_path[0]
            required = split_path[1] if len(split_path) > 1 else False
            extracted = self._extract(json_obj, search_path, required, True)
            new_json[key] = extracted
        new_json["mapipieline_added_labels"] = json_obj.pop("mapipieline_added_labels")
        if json_obj:
            pass
            # raise Exception(obj_type + " why is this not empty: " + str(json_obj))
        
        # put back the data
        for k, v in new_json.items():
            json_obj[k] = v
    def _remove_common_fields(self, json_obj):
        for k in self.REMOVED_VALUES:
            json_obj.pop(k, None)
    
    # extracts and stores custom labels in "mapipieline_added_labels" filed
    # to be later saved in the repository layer
    def _add_labels(self, obj):
        labels = set()
        print("addinglabels for : " + obj["id"])
        print(obj)
        print("before")
        mapping = self.load_mapping_cache(obj["type"])
        for label_path in mapping["derived_labels"]:
            split_path = label_path.split("@", 1)
            search_path = split_path[0]
            required = split_path[1] if len(split_path) > 1 else False
            extracted_labels = self._extract(obj, search_path, required)
            if not extracted_labels:
                continue
            
            # either a list of labels or a singular value
            if not isinstance(extracted_labels, list):
                extracted_labels = [extracted_labels]
            for label in extracted_labels:
                label = lib.constants.clean_label_str(label)
                labels.add(label)
        obj["mapipieline_added_labels"] = labels
        print("after")

    # lazily loads in mappings
    def load_mapping_cache(self, resource_type):
        # TODO: Tempororay substitute
        if resource_type == "sub-attack-pattern":
            resource_type = "attack-pattern"
            
        if resource_type in self.mapping_cache:
            return self.mapping_cache[resource_type]
        
        filepath = os.path.join(self.MAPPING_BASE, self.domain, resource_type + ".json")
        if not os.path.isfile(filepath):
            raise Exception("Could not find mappings for: " + resource_type)
        with open(filepath, "r") as f:
            self.mapping_cache[resource_type] = json.load(f)
        return self.mapping_cache[resource_type]
    
    # dig in json object using path
    def _extract(self, json_obj, path, required=False, toDelete=False):
        if path == "[*]":
            raise Exception("Invalid Path")
        filtered_path = path.split(".")
        try:
            return self._recursive_json_dig(None, filtered_path, json_obj, 0, toDelete)
        except KeyError:
            print("what the fuck: " + str(required))
            print(json_obj)
            print(path)
            if required:
                raise Exception("unable to find key: " + path)
    def _recursive_json_dig(self, parent, operations, jsonobj, iterator, toDelete):
        op = operations[iterator]

        if not (op[0] == "[" and op[-1] == "]"):
            if iterator == len(operations) - 1:
                return jsonobj[op] if not toDelete else jsonobj.pop(op)
            return self._recursive_json_dig(jsonobj, operations, jsonobj[op], iterator + 1, toDelete)
        index = op[1:len(op) - 1]
        if index == "*":
            if iterator == len(operations) - 1:
                if toDelete:
                    op = operations[iterator - 1]
                    if not (op[0] == "[" and op[-1] == "]"):
                        return parent.pop(op)
                    if not op == "*":
                        return parent.pop(int(op))
                
                # so nice
                return jsonobj
                # very nice
            combined = []
            for elem in jsonobj:
                dig_result = self._recursive_json_dig(jsonobj, operations, elem, iterator + 1, toDelete)
                if not isinstance(dig_result, list):
                    dig_result = [dig_result]
                combined = combined + dig_result
            return combined
        else:
            if iterator == len(operations) - 1:
                return jsonobj[int(index)] if not toDelete else jsonobj.pop(int(index))
            return self._recursive_json_dig(jsonobj, operations, jsonobj[int(index)], iterator + 1, toDelete)