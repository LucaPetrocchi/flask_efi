from app import ma
from marshmallow import fields

class UsuarioSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    nombre = fields.String()
    correo = fields.String()

class UsuarioAdminSchema(UsuarioSchema):
    password = fields.String()
    is_admin = fields.Boolean()
    fecha_creacion = fields.DateTime()

class TagSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    nombre = fields.String()

class PostTagsSchema(ma.Schema):
    post_id = fields.Integer()
    tag_id = fields.Integer()
    # deberian ser dump true?

class PostSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    titulo = fields.String()
    contenido = fields.String()
    fecha = fields.DateTime()
    usuario_id = fields.Integer()
    usuario_obj = fields.Nested(UsuarioSchema, exclude={'id'})
    # hay manera de hacer que el comentario sea un subtipo de esto?
    # o al reves? porque son lo mismo con menos info

class ComentarioSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    contenido = fields.String()
    fecha = fields.DateTime()
    usuario_id = fields.Integer()
    usuario_obj = fields.Nested(UsuarioSchema, exclude={'id'})



