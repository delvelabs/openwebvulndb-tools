import json


def serialize(schema, data, *, indent=4):
    data, errors = schema.dump(data)
    clean_walk(data)
    return json.dumps(data, indent=indent), errors


def clean_walk(data):
    if isinstance(data, list):
        for item in data:
            clean_walk(item)
    elif isinstance(data, dict):
        to_remove = set()
        for key, val in data.items():
            if val is None or val == []:
                to_remove.add(key)
            else:
                clean_walk(val)

        for key in to_remove:
            del data[key]
