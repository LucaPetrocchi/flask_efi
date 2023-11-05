from datetime import timedelta

from flask import (
    jsonify, 
    request,
    abort,
)
from flask.views import MethodView
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)
from sqlalchemy.exc import SQLAlchemyError
from marshmallow.exceptions import ValidationError
from app import app, db, jwt
from models.models import (
    Usuario,
    Post,
    Tag,
    Post,
    Comentario,
)
from schemas.schemas import (
    UsuarioSchema,
    UsuarioAdminSchema,
    TagSchema,
    PostSchema,
    ComentarioSchema,
)

from error_handlers import *

def get_permissions():
    try:
        verify_jwt_in_request()
        additional_info = get_jwt() 
        return additional_info['is_admin']
    except:
        raise UnauthorizedError('Token incorrecto, o no se ha provisto token')

def validate_permissions(errmsg):
    try:
        assert get_permissions()
    except:
        raise UnauthorizedError(f'No tiene permisos para esta acción: {errmsg}')

def id_provided_is_none(id):
    if id is None:
        raise APIAuthError('No se ha provisto id')

class Login(MethodView):
    def post(self):
        if "nombre" not in request.json:
            raise APIAuthError('No se introdujo usuario')

        if "password" not in request.json:
            raise APIAuthError('No se introdujo contraseña')

        nombre = request.json.get('nombre')
        password = request.json.get('password')

        usuario = Usuario.query.filter_by(nombre=nombre).first()    

        if not usuario:
            raise NotFoundError('Usuario no existe')

        if usuario and check_password_hash(usuario.password, password):
            access_token = create_access_token(
                identity = nombre,
                expires_delta = timedelta(minutes=120),
                additional_claims = dict(
                    is_admin = usuario.is_admin,
                )
            )
            return jsonify({'Exitoso': access_token}), 200
        raise UnauthorizedError('Contraseña no coincide')
app.add_url_rule(
    '/login', 
    view_func=Login.as_view('login')
    )

class UsuarioAPI(MethodView):
    def get(self, usuario_id=None):
        admin_perms = get_permissions()

        if usuario_id == None and admin_perms == False:
            usuarios = Usuario.query.all()
            usuarios_schema = UsuarioSchema(
            ).dump(usuarios, many=True) 

        elif usuario_id is not None and admin_perms == False:
            usuarios = Usuario.query.get(usuario_id)
            usuarios_schema = UsuarioSchema(
            ).dump(usuarios)

        elif usuario_id == None and admin_perms == True:
            usuarios = Usuario.query.all()
            usuarios_schema = UsuarioAdminSchema(
            ).dump(usuarios, many=True) 

        elif usuario_id is not None and admin_perms == True:
            usuarios = Usuario.query.get(usuario_id)
            usuarios_schema = UsuarioAdminSchema(
            ).dump(usuarios)

        if not usuarios_schema:
            raise NotFoundError('No se ha encontrado usuario')

        return jsonify(usuarios_schema), 200

    def post(self):
        try:
            usuario_json = UsuarioAdminSchema().load(request.json)
        except:
            raise APIAuthError('Fallo de validación')
        nombre = usuario_json.get('nombre')
        correo = usuario_json.get('correo')
        password_plain = usuario_json.get('password')
        password = generate_password_hash(
            password_plain, method='pbkdf2', salt_length=16
        )

        is_admin = usuario_json.get('is_admin')

        already_exists = Usuario.query.filter_by(nombre=nombre).first()
        if already_exists:
            raise ConflictError('Nombre ya en uso')

        if is_admin:
            validate_permissions(errmsg='dar privilegios administrativos')
        
        try:
            nuevo_usuario = Usuario(
                nombre = nombre,
                correo = correo,
                password = password,
                is_admin = is_admin,
            )
            db.session.add(nuevo_usuario)
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)


        return jsonify({'Exitoso': UsuarioSchema().dump(usuario_json)}, 200)

    def put(self, usuario_id=None):
        id_provided_is_none(usuario_id)

        usuario = Usuario.query.get(usuario_id)

        if not usuario:
            raise NotFoundError('No se encontró usuario')

        try:
            usuario_json = UsuarioAdminSchema().load(request.json)
        except:
            raise APIAuthError('Fallo de validación')
        
        nombre = usuario_json.get('nombre')
        correo = usuario_json.get('correo')
        password = usuario_json.get('password')
        is_admin = usuario_json.get('is_admin')

        try: 
            if nombre is not None:
                usuario.nombre = nombre
            if correo is not None:
                usuario.correo = correo
            if password is not None:
                usuario.password = generate_password_hash(
                    password, method='pbkdf2', salt_length=16
                )
            if is_admin is not None:
                validate_permissions(errmsg='dar privilegios administrativos')
                usuario.is_admin = is_admin
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)


        return jsonify({'Exitoso': UsuarioAdminSchema().dump(usuario)}, 200)
        
    def delete(self, usuario_id=None):
        id_provided_is_none(usuario_id)
        validate_permissions(errmsg='borrar usuarios')

        usuario = Usuario.query.get(usuario_id)

        if not usuario:
            raise NotFoundError('No se encontró usuario')

        dump = UsuarioAdminSchema().dump(usuario)

        try:
            db.session.delete(usuario)
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)
        
        return jsonify({'Borrado': dump}), 410
app.add_url_rule(
    '/usuario', 
    view_func=UsuarioAPI.as_view('usuario')
)
app.add_url_rule(
    '/usuario/<usuario_id>',
    view_func=UsuarioAPI.as_view('usuario_por_id')
)

class TagAPI(MethodView):
    def __init__(self):
        validate_permissions(errmsg='editar tags')

    def get(self, tag_id=None):
        if tag_id is not None:
            tags = Tag.query.get(tag_id)
            tags_schema = TagSchema(
            ).dump(tags)
        else:
            tags = Tag.query.all()
            tags_schema = TagSchema(
            ).dump(tags, many=True)

        if not tags_schema:
            raise NotFoundError('No se ha encontrado tag')


        return jsonify(tags_schema)
    
    def post(self):
        try:
            tag_json = TagSchema().load(request.json)
        except:
            raise APIAuthError('Error de validación')
    
        nombre = tag_json.get('nombre')

        already_exists = Tag.query.filter_by(nombre=nombre).first()
        if already_exists:
            raise ConflictError('Tag ya existe')
        
        try:
            nuevo_tag = Tag(nombre=nombre)
            db.session.add(nuevo_tag)
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)
        
        return jsonify({'Exitoso': TagSchema().dump(tag_json)}), 201
        
    def put(self, tag_id=None):
        id_provided_is_none(tag_id)

        tag = Tag.query.get(tag_id)
        if not tag:
            raise NotFoundError('No se encontró tag')

        try:
            tag_json = TagSchema().load(request.json)
        except:
            raise APIAuthError('Error de validación')
        
        nombre = tag_json.get('nombre')

        try:
            tag.nombre = nombre
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)

        return jsonify({'Exitoso': TagSchema().dump(tag)}), 200
        
    def delete(self, tag_id=None):
        id_provided_is_none(tag_id)

        tag = Tag.query.get(tag_id)
        if not tag:
            raise NotFoundError('No se encontró tag')

        dump = TagSchema().dump(tag)
        try:
            db.session.delete(tag)
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)
        return jsonify({'Borrado': dump}), 410
app.add_url_rule(
    '/tag',
    view_func=TagAPI.as_view('tag')
)
app.add_url_rule(
    '/tag/<tag_id>',
    view_func=TagAPI.as_view('tag_por_id')
)

class PostAPI(MethodView):
    def get(self, post_id=None):
        if post_id is not None:
            posts = Post.query.get(post_id)
            posts_schema = PostSchema(
            ).dump(posts)
        else:
            posts = Post.query.all()
            posts_schema = PostSchema(
            ).dump(posts, many=True)

        if not posts_schema:
            raise NotFoundError('No se ha encontrado usuario')


        return jsonify(posts_schema), 200

    def post(self):
        post_info = {req: request.json[req] for req in request.json if req not in 'tags'}
        tags = request.json['tags']

        try:
            post_json = PostSchema().load(post_info)
        except:
            raise APIAuthError('Error de validación')
        
        titulo = post_json.get('titulo')
        contenido = post_json.get('contenido')
        usuario_id = post_json.get('usuario_id')

        nuevo_post = Post(
            titulo=titulo,
            contenido=contenido,
            usuario_id=usuario_id,
        )
        
        for tag_id in tags:
            tag = Tag.query.filter_by(id = tag_id).first()
            if tag is not None:
                nuevo_post.tags.append(tag)

        try:
            db.session.add(nuevo_post)
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)

        return jsonify({'Exitoso': PostSchema().dump(nuevo_post)}), 201
    
    def put(self, post_id=None):
        id_provided_is_none(post_id)
        
        post = Post.query.get(post_id)
        if not post:
            raise NotFoundError('Post no existe')

        nuevo_post = {req: request.json[req] for req in request.json if req not in 'tags'}
        try:
            post_json = PostSchema().load(nuevo_post)
        except:
            raise APIAuthError('Error de validación')
        
        titulo = post_json.get('titulo')
        contenido = post_json.get('contenido')
        tags = request.json['tags']

        try:
            if titulo is not None:
                post.titulo = titulo
            if contenido is not None:
                post.contenido = contenido
            if tags is not None:
                post.tags.clear() # hace falta hacer esto mas eficiente?
                # capaz con una variable en el query -- "delete" o "append"
                for tag_id in tags:
                    tag = Tag.query.filter_by(id = tag_id).first()
                    if tag is not None:
                        post.tags.append(tag)
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)
    
            
        return jsonify({'Exitoso': PostSchema().dump(post)}, 200)

    def delete(self, post_id=None):
        id_provided_is_none(post_id)
        
        post = Post.query.get(post_id)
        dump = PostSchema().dump(post)
        try:
            post.tags.clear()
            db.session.delete(post)
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)

        return jsonify({'Borrado': dump}), 410
app.add_url_rule(
    '/post',
    view_func=PostAPI.as_view('post')
)
app.add_url_rule(
    '/post/<post_id>',
    view_func=PostAPI.as_view('post_por_id')
)

class ComentarioAPI(MethodView):
    def get(self, comentario_id=None):
        if comentario_id is not None:
            comentarios = Comentario.query.get(comentario_id)
            comentarios_schema = ComentarioSchema(
            ).dump(comentarios)
        else:
            comentarios = Comentario.query.all()
            comentarios_schema = ComentarioSchema(
            ).dump(comentarios, many=True)

        if not comentarios_schema:
            raise NotFoundError('No se ha encontrado usuario')

        
        return jsonify(comentarios_schema), 200
    
    def post(self):
        try:
            comentario_json = ComentarioSchema().load(request.json)
        except:
            raise APIAuthError('Error de validación')

        post_id = comentario_json.get('post_id')
        contenido = comentario_json.get('contenido')
        usuario_id = comentario_json.get('usuario_id')

        try:
            nuevo_comentario = Comentario(
                post_id = post_id,
                contenido = contenido,
                usuario_id = usuario_id
            )
            db.session.add(nuevo_comentario)
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)

        return jsonify({'Exitoso': ComentarioSchema().dump(comentario_json)}, 201)

    def put(self, comentario_id=None):
        id_provided_is_none(comentario_id)

        comentario = Comentario.query.get(comentario_id)
        if not comentario:
            raise NotFoundError('Comentario no existe')

        comentario_json = ComentarioSchema().load(request.json)
        contenido = comentario_json.get('contenido')

        try:
            comentario.contenido = contenido
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)

        return jsonify({'Exitoso': ComentarioSchema().dump(comentario)}, 200)

    def delete(self, comentario_id=None):
        id_provided_is_none(comentario_id)

        comentario = Comentario.query.get(comentario_id)
        if not comentario:
            raise NotFoundError('Comentario no existe')

        dump = ComentarioSchema().dump(comentario)
        try:
            db.session.delete(comentario)
            db.session.commit()
        except SQLAlchemyError as err:
            mensaje = str(err.orig)
            raise ConflictError(mensaje)
            
        return jsonify({'Borrado': dump}), 410
app.add_url_rule(
    '/comentario',
    view_func=ComentarioAPI.as_view('comentario')
)
app.add_url_rule(
    '/comentario/<comentario_id>',
    view_func=ComentarioAPI.as_view('comentario_por_id')
)