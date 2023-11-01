from datetime import datetime, timedelta

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
    PostTagsSchema,
    PostSchema,
    ComentarioSchema,
)

class Login(MethodView):
    def post(self):
        # data = request.authorization

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
    def __init__(self):
       verify_jwt_in_request()

    def get(self, usuario_id=None):
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
        additional_info = get_jwt()
        if not additional_info['is_admin']:
            return jsonify(Denegado='No tiene autorización') 

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
        if is_admin is not None:
            usuario.is_admin = is_admin
        
        db.session.commit()

        return jsonify({'Exitoso': UsuarioAdminSchema().dump(usuario)}, 200)
        
    def delete(self, usuario_id):
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
            return jsonify(Denegado='No tiene autorización')
        
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
        
        tag = Tag.query.get(tag_id)
        tag_json = TagSchema().load(request.json)

        nombre = tag_json.get('nombre')

        tag.nombre = nombre

        db.session.commit()

        return jsonify({'Exitoso': TagSchema().dump(tag)}, 200)
        
    def delete(self, tag_id):
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
