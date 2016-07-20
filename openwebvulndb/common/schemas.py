import json

from marshmallow import Schema, fields, validate, post_load
from .models import Meta, Repository


class RepositorySchema(Schema):
    class Meta:
        ordered = True

    type = fields.String(required=True)
    location = fields.Url(required=True)

    @post_load
    def make(self, data):
        return Repository(**data)


class MetaSchema(Schema):
    class Meta:
        ordered = True

    key = fields.String(required=True)
    name = fields.String(required=False, allow_none=True)
    url = fields.Url(required=False, allow_none=True)
    repositories = fields.Nested(RepositorySchema, many=True, required=False)

    @post_load
    def make(self, data):
        return Meta(**data)


def serialize(schema, data):
    data, errors = schema.dump(data)
    clean_walk(data)
    return json.dumps(data, indent=4), errors


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
