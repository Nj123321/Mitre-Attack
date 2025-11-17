# hacky shared lib solution
import sys, os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
# hacky solution --- end

import json
import stix2
import time

mobile = "mobile-attack/mobile-attack.json"
ent = "enterprise-attack/enterprise-attack.json"
ics = "ics-attack/ics-attack.json"

import os

from mitre_common.commons import clean_str

project_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(project_base)
fn = project_base + "/attack-stix-injestion/resources/mitre-attack-data/" + mobile

creating_new_mappings = True

with open(fn, "r", encoding="utf-8") as f:
    bundle_dict = json.load(f)

# Parse into a Bundle object (and parse contained objects into STIX SDO/SROs)
bundle = stix2.parse(bundle_dict, version="2.1", allow_custom=True)
stix2.Filter

# bundle is a stix2 Bundle object; bundle.objects is a list of stix2 objects
countz = {}


def extract(json_obj, path, toDelete=False):
        if path == "[*]":
            raise Exception("Invalid Path")
        filtered_path = path.split(".")
        return recursive_json_dig(None, filtered_path, json_obj, 0, toDelete)
def recursive_json_dig(parent, operations, jsonobj, iterator, toDelete):
    op = operations[iterator]

    if not (op[0] == "[" and op[-1] == "]"):
        if iterator == len(operations) - 1:
            return jsonobj[op] if not toDelete else jsonobj.pop(op)
        return recursive_json_dig(jsonobj, operations, jsonobj[op], iterator + 1, toDelete)
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
            dig_result = recursive_json_dig(jsonobj, operations, elem, iterator + 1, toDelete)
            if not isinstance(dig_result, list):
                dig_result = [dig_result]
            combined = combined + dig_result
        return combined
    else:
        if iterator == len(operations) - 1:
            return jsonobj[int(index)] if not toDelete else jsonobj.pop(int(index))
        return recursive_json_dig(jsonobj, operations, jsonobj[int(index)], iterator + 1, toDelete)

# graph = Graph("bolt://localhost:7687")

domain = ""
id_mapping = {}
print("Bundle contains", len(bundle.objects), "objects")
for obj in bundle.objects:
    name = obj.__class__.__name__
    if name == "dict":
        name = obj["type"]
        if name == "x-mitre-matrix":
            domain = obj["external_references"][0]["external_id"]
    if not isinstance(obj, dict):
        obj = obj.__dict__['_inner']
        name = obj['type']
    
    try:
        id_mapping[name]
    except KeyError:
        id_mapping[name] = []
    # print("whatthefuck: " + id_mapping[name].ser)
    id_mapping[name].append(obj)

print("found domain: " + domain)
# input("Enter something: ")
    
for k, v in id_mapping.items():
    print("k: " + str(k) + "   |  length: " + str(len(v)))

# intialize keys to look for
keys_to_look_for = set(["woop"])
keys_to_look_for_hash = {}
for key in keys_to_look_for:
    keys_to_look_for_hash[key] = set()
    
intersection = set()

bad_model = [
    "marking-definition",
    "relationship",
]

# find attirbutes per model
att_to_look = ["kill_chain_phases"]

# mappings
bad_att = [
    ""
]
import os
directory = "/Users/nathan.jin/Desktop/work/mitreattack/attack-stix-injestion/resources/mappings/" + domain + "/"

# pre-compute intersection
for name, obj_array in id_mapping.items():
    attribute_value_collector = {}
    for att in att_to_look:
        attribute_value_collector[att] = set()
    common_attributes = set()
    first = True
    for elem in obj_array:
        for keys in elem:
            if not keys in common_attributes:
                if first:
                    common_attributes.add(keys)
                else:
                    try:
                        common_attributes.remove(keys)
                    except KeyError:
                        pass
        if first:
            first = False
    if name in bad_model:
        continue
    # if name.startswith("x-mitre"):
    # continue
    print("DEBUG - intersection: " + name)
    if len(intersection) == 0:
        intersection = common_attributes
    else:
        intersection = intersection.intersection(common_attributes)

common_labels = [""]

for name, obj_array in id_mapping.items():
    print("======================" + name)
    # mappings
    file_path = os.path.join(directory, name + ".json")
    mapping_creator = {}
    mapping_creator["derived_attributes"] = {}
    mapping_creator["derived_labels"] = []
    if name not in ["relationship", "identity", "marking-definition"]:
        mapping_creator["derived_labels"].append("x_mitre_domains")
    
    mapping_creator["attributes"] = {}
    mapping_creator["delete"] = []
    
    attribute_value_collector = {}
    for att in att_to_look:
        attribute_value_collector[att] = set()
    
    attributez = set()
    common_attributes = set()
    first = True
    for elem in obj_array:
        if elem["id"] == "malware--0a9c51e0-825d-4b9b-969d-ce86ed8ce3c3":
            print(elem)
        for keys in elem:
            if keys in keys_to_look_for:
                keys_to_look_for_hash[keys].add(name)
            # total aggregator
            attributez.add(keys)
            # local aggregator
            if not keys in common_attributes:
                if first:
                    common_attributes.add(keys)
                else:
                    try:
                        common_attributes.remove(keys)
                    except KeyError:
                        pass
            if keys in att_to_look:
                found_values = extract(elem, "kill_chain_phases.[*].phase_name")
                if not isinstance(found_values, list):
                    found_values = [found_values]
                for value in found_values:
                    value = clean_str(value)
                    attribute_value_collector[keys].add(value)
            # global aggregator / intersector
        elem
        if first:
            first = False
    print("COLLECTED: ")
    for k in att_to_look:
        if len(attribute_value_collector[k]) == 0:
            attribute_value_collector.pop(k)
    print(attribute_value_collector)
    
    
    
    # attributez = attributez.difference(intersection)
    # common_attributes = common_attributes.difference(intersection)
    print("TOTAL ATTRIBUTES: ")
    temp = list(attributez)
    temp.sort()
    print(temp)
    
    total_att = temp
    
    print("COMMON ATTRIBUTES: ")
    temp = list(common_attributes)
    temp.sort()
    print(temp)
    
    # build mapping
    for att in total_att:
        if att in bad_att:
            mapping_creator["delete"].append(att)
        else:
            if att == "id":
                mapping_creator["attributes"]["stix_uuid"] = att
            else:
                mapping_creator["attributes"][att] = att
        #labels
        if att == "kill_chain_phases":
            mapping_creator["derived_attributes"]["related_tactics"] = "kill_chain_phases.[*].phase_name"
        # if att == "x_mitre_platforms":
            # mapping_creator["derived_labels"].append("x_mitre_platforms")
        if att == "external_references" and name != "relationship":
            mapping_creator["derived_attributes"]["attack_id"] = "external_references.[0].external_id"
    
    for derived_att in mapping_creator["derived_attributes"]:
        mapping_creator["attributes"][derived_att] = derived_att
    if creating_new_mappings:
        with open(file_path, "w") as f:
            json.dump(mapping_creator, f, indent=4)
        print("created mappings for: " + file_path)
            
    if name in bad_model:
        print("=======end===============")
        continue
    # if name.startswith("x-mitre"):
        # print("=======end===============")
        # continue
    print("=======end===============")
    # if name == "Relationship":
        # knows = Relationship(id_mapping[obj.source_ref], obj.relationship_type, id_mapping[obj.target_ref])
        # graph.create(knows)
    # else:
        # n = Node(obj_json["type"], **obj_json)
        # id_mapping[id] = n
        # graph.create(n)
# for k,v in keys_to_look_for_hash:
#     print("foundkey: " + k)
#     print("for:")
#     print(v)
temp = list(intersection)
temp.sort()
print(temp)

    # print(obj["type"], obj["id"], getattr(obj, "name", None))

# catcher = set()
# for name, obj_array in id_mapping.items():
#     for obj in obj_array:
#         try:
#             for keychain in obj["kill_chain_phases"]:
#                 catcher.add(keychain["phase_name"].replace("-", ""))
#         except KeyError:
#             pass
# print("------")
# print(catcher)

# catcher = set()
# first = True
# for name, obj_array in id_mapping.items():
#     for obj in obj_array:
#         for k, v in obj_array:
#             if first:
#                 catcher.add(k)
#             else:
#                 for names in catcher:
#                     try:
#                         obj_array[names]
#                     except KeyError:
#                         catcher.remove(names)
#         if first:
#             first= False
# print("------")
# print(catcher)


# obj = {"type": "malware", "id": "malware--2", "name": "Emotet"}
# node = Node(obj["type"], **obj)  # label = "malware", dynamic
# graph.create(node)