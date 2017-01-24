from marshmallow import Schema, fields, post_load
from .vane2models import File, Signature, FilesList


class SignatureSchema(Schema):
    class Meta:
        ordered = True

    hash = fields.String(required=True)
    algo = fields.String(required=True)
    versions = fields.List(fields.String, required=False)

    @post_load
    def make(self, data):
        return Signature(**data)


class FileSchema(Schema):
    class Meta:
        ordered = True

    path = fields.String(required=True)
    signatures = fields.Nested(SignatureSchema, many=True, required=False)

    @post_load
    def make(self, data):
        return File(**data)


class FilesListSchema(Schema):
    class Meta:
        ordered = True

    key = fields.String(required=True)
    producer = fields.String(required=True)
    files = fields.Nested(FileSchema, many=True, required=False)

    @post_load
    def make(self, data):
        return FilesList(**data)
