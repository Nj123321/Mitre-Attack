from enum import Enum

class CustomPipelineKeys(Enum):
    EXTRACTED_TYPE = "extracted_type"
    INT_MODIFIED = "int_modified"

def clean_str(label):
    label = label.lower().replace(" ", "").replace("/", "").replace("-","")
    return label

def extract_from_json(json_obj, path, required=False, toDelete=False):
    if path == "[*]":
        raise Exception("Invalid Path")
    filtered_path = path.split(".")
    try:
        return _recursive_json_dig(None, filtered_path, json_obj, 0, toDelete)
    except KeyError:
        if required:
            raise Exception("unable to find key: " + path + "\n for: \n" + str(json_obj))
def _recursive_json_dig(parent, operations, jsonobj, iterator, toDelete):
    op = operations[iterator]

    if not (op[0] == "[" and op[-1] == "]"):
        if iterator == len(operations) - 1:
            return jsonobj[op] if not toDelete else jsonobj.pop(op)
        return _recursive_json_dig(jsonobj, operations, jsonobj[op], iterator + 1, toDelete)
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
            dig_result = _recursive_json_dig(jsonobj, operations, elem, iterator + 1, toDelete)
            if not isinstance(dig_result, list):
                dig_result = [dig_result]
            combined = combined + dig_result
        return combined
    else:
        if iterator == len(operations) - 1:
            return jsonobj[int(index)] if not toDelete else jsonobj.pop(int(index))
        return _recursive_json_dig(jsonobj, operations, jsonobj[int(index)], iterator + 1, toDelete)