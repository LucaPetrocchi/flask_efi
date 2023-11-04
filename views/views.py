from datetime import datetime, timedelta
import json

from flask import (
    jsonify, 
    request,
)
from flask.views import MethodView
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from sqlalchemy import ForeignKey
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from app import app, db, jwt
from models.models import (
    Usuario,
    Post,
    Tag,
    post_tags,
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

class Login(MethodView):
    def post(self):
        nombre = request.json.get('nombre')
        password = request.json.get('password')

        usuario = Usuario.query.filter_by(nombre=nombre).first()
        if usuario and check_password_hash(usuario.password, password):
            access_token = create_access_token(
                identity = nombre,
                expires_delta = timedelta(minutes=120),
                additional_claims = dict(
                    is_admin = usuario.is_admin,
                )
            )
            return jsonify({'ok': access_token})
        return jsonify(Error='No se pudo generar token')
app.add_url_rule(
    '/login', 
    view_func=Login.as_view('login')
    )

class UsuarioAPI(MethodView):
    # def __init__(self):
    #    verify_jwt_in_request()

    def get(self, usuario_id=None):
        verify_jwt_in_request()
        additional_info = get_jwt() # hay manera de hacer que esta var sea global a la API?
        is_admin = additional_info['is_admin']

        if usuario_id == None and is_admin == False:
            usuarios = Usuario.query.all()
            usuarios_schema = UsuarioSchema(
            ).dump(usuarios, many=True) 

        elif usuario_id is not None and is_admin == False:
            usuarios = Usuario.query.get(usuario_id)
            usuarios_schema = UsuarioSchema(
            ).dump(usuarios)

        elif usuario_id == None and is_admin == True:
            usuarios = Usuario.query.all()
            usuarios_schema = UsuarioAdminSchema(
            ).dump(usuarios, many=True) 

        elif usuario_id is not None and is_admin == True:
            usuarios = Usuario.query.get(usuario_id)
            usuarios_schema = UsuarioAdminSchema(
            ).dump(usuarios)
        
        return jsonify(usuarios_schema)

    def post(self):
        usuario_json = UsuarioAdminSchema().load(request.json)
        nombre = usuario_json.get('nombre')
        correo = usuario_json.get('correo')
        password_plain = usuario_json.get('password')
        password = generate_password_hash(
            password_plain, method='pbkdf2', salt_length=16
        )
        is_admin = usuario_json.get('is_admin')
                
        already_exists = Usuario.query.filter_by(nombre=nombre).first()
        if already_exists:
            return jsonify(Error='Este nombre ya está en uso')

        nuevo_usuario = Usuario(
            nombre = nombre,
            correo = correo,
            password = password,
            is_admin = is_admin,
        )

        db.session.add(nuevo_usuario)
        db.session.commit()

        return jsonify({'Exitoso': UsuarioSchema().dump(usuario_json)}, 200)

    def put(self, usuario_id):
        verify_jwt_in_request()
        additional_info = get_jwt() 
        if usuario_id is None:
            return jsonify(Error='No se ha provisto id de usuario')

        usuario = Usuario.query.get(usuario_id)
        usuario_json = UsuarioAdminSchema().load(request.json)

        nombre = usuario_json.get('nombre')
        correo = usuario_json.get('correo')
        password = usuario_json.get('password')
        is_admin = usuario_json.get('is_admin')

        if nombre is not None:
            usuario.nombre = nombre
        if correo is not None:
            usuario.correo = correo
        if password is not None:
            usuario.password = generate_password_hash(
                password, method='pbkdf2', salt_length=16
            )
        if is_admin is not None and additional_info['is_admin']:
            usuario.is_admin = is_admin
        if is_admin is not None and not additional_info['is_admin']:
            return jsonify(Error='No posee autorización para cambiar permisos de usuarios.')

        db.session.commit()

        return jsonify({'Exitoso': UsuarioAdminSchema().dump(usuario)}, 200)
        
    def delete(self, usuario_id):
        verify_jwt_in_request()
        additional_info = get_jwt() 

        if additional_info['is_admin'] == False:
            return jsonify(Error='No posee autorización para borrar usuarios')
        if usuario_id is None:
            return jsonify(Error='No se ha provisto id de usuario')
        
        usuario = Usuario.query.get(usuario_id)
        dump = UsuarioAdminSchema().dump(usuario)
        db.session.delete(usuario)
        db.session.commit()
        return jsonify({'Borrado': dump})
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
        verify_jwt_in_request()

    def get(self, tag_id=None):
        if tag_id is not None:
            tags = Tag.query.get(tag_id)
            tags_schema = TagSchema(
            ).dump(tags)
        else:
            tags = Tag.query.all()
            tags_schema = TagSchema(
            ).dump(tags, many=True)
        return jsonify(tags_schema)
    
    def post(self):
        additional_info = get_jwt()
        if not additional_info['is_admin']:
            return jsonify(Denegado='No tiene autorización para crear tags')
        
        tag_json = TagSchema().load(request.json)
        nombre = tag_json.get('nombre') # manera de hacer esto en una línea?

        already_exists = Tag.query.filter_by(nombre=nombre).first()
        if already_exists:
            return jsonify(Error='Este tag ya existe')
        
        nuevo_tag = Tag(nombre=nombre)

        db.session.add(nuevo_tag)
        db.session.commit()
        
        return jsonify({'Exitoso': TagSchema().dump(tag_json)}, 200)
        
    def put(self, tag_id):
        if tag_id is None:
            return jsonify(Error='No se ha provisto id de tag')
        
        additional_info = get_jwt()
        if not additional_info['is_admin']:
            return jsonify(Denegado='No tiene autorización para editar tags')

        tag = Tag.query.get(tag_id)
        tag_json = TagSchema().load(request.json)

        nombre = tag_json.get('nombre')

        tag.nombre = nombre

        db.session.commit()

        return jsonify({'Exitoso': TagSchema().dump(tag)}, 200)
        
    def delete(self, tag_id):
        additional_info = get_jwt()
        if not additional_info['is_admin']:
            return jsonify(Denegado='No tiene autorización para borrar tags')

        if tag_id is None:
            return jsonify(Error='No se ha provisto id de tag')

        tag = Tag.query.get(tag_id)
        dump = TagSchema().dump(tag)
        db.session.delete(tag)
        db.session.commit()
        return jsonify({'Borrado': dump})
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
        return jsonify(posts_schema)

    def post(self):
        post_info = {req: request.json[req] for req in request.json if req not in 'tags'}
        tags = request.json['tags']

        post_json = PostSchema().load(post_info)
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
            nuevo_post.tags.append(tag)

        db.session.add(nuevo_post)
        db.session.commit()

        print(nuevo_post.tags)

        return jsonify({'Exitoso': PostSchema().dump(nuevo_post)}, 200)
    
    def put(self, post_id):
        if post_id is None:
            return jsonify(Error='No se ha provisto id de post')
        
        post = Post.query.get(post_id)
        nuevo_post = {req: request.json[req] for req in request.json if req not in 'tags'}
        post_json = PostSchema().load(nuevo_post)
        # cambiar todo esto del dic por comprension a una funcion

        titulo = post_json.get('titulo')
        contenido = post_json.get('contenido')
        tags = request.json['tags']

        if titulo is not None:
            post.titulo = titulo
        if contenido is not None:
            post.contenido = contenido
        if tags is not None:
            post.tags.clear() # hace falta hacer esto mas eficiente?
            # capaz con una variable en el query -- "delete" o "append"
            for tag_id in tags:
                tag = Tag.query.filter_by(id = tag_id).first()
                post.tags.append(tag)
        
        db.session.commit()

        return jsonify({'Exitoso': PostSchema().dump(post)}, 200)

    def delete(self, post_id):
        if post_id is None:
            return jsonify(Error='No se ha provisto id de post')
        
        post = Post.query.get(post_id)
        dump = PostSchema().dump(post)
        post.tags.clear()
        db.session.delete(post)
        db.session.commit()
        return jsonify({'Borrado': dump})
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
        return jsonify(comentarios_schema)
    def post(self):
        comentario_json = ComentarioSchema().load(request.json)

        post_id = comentario_json.get('post_id')
        contenido = comentario_json.get('contenido')
        usuario_id = comentario_json.get('usuario_id')

        nuevo_comentario = Comentario(
            post_id = post_id,
            contenido = contenido,
            usuario_id = usuario_id
        )

        db.session.add(nuevo_comentario)
        db.session.commit()

        return jsonify({'Exitoso': ComentarioSchema().dump(comentario_json)}, 200)

    def put(self, comentario_id=None):
        if comentario_id is None:
            return jsonify(Error='No se ha provisto id de comentario')

        comentario = Comentario.query.get(comentario_id)
        comentario_json = ComentarioSchema().load(request.json)

        contenido = comentario_json.get('contenido')

        comentario.contenido = contenido

        db.session.commit()

        return jsonify({'Exitoso': ComentarioSchema().dump(comentario)}, 200)

    def delete(self, comentario_id=None):
        if comentario_id is None:
            return jsonify(Error='No se ha provisto id de comentario')
    
        comentario = Comentario.query.get(comentario_id)
        dump = ComentarioSchema().dump(comentario)
        db.session.delete(comentario)
        db.session.commit()
        return jsonify({'Borrado': dump})

app.add_url_rule(
    '/comentario',
    view_func=ComentarioAPI.as_view('comentario')
)
app.add_url_rule(
    '/comentario/<comentario_id>',
    view_func=ComentarioAPI.as_view('comentario_por_id')
)