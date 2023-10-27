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

        user = Usuario.query.filter_by(nombre=nombre).first()
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(
                identity = nombre,
                expires_delta = timedelta(minutes=120),
                additional_claims = dict(
                    is_admin = user.is_admin,
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
        if usuario_id == None:
            usuarios = Usuario.query.all()
            usuarios_schema = UsuarioSchema(
            ).dump(usuarios, many=True)
        else:
            usuarios = Usuario.query.get(usuario_id)
            usuarios_schema = UsuarioSchema(
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
            return jsonify(error='Este nombre ya está en uso')

        nuevo_usuario = Usuario(
            nombre = nombre,
            correo = correo,
            password = password,
            is_admin = is_admin,
        )

        db.session.add(nuevo_usuario)
        db.session.commit()

        return jsonify({'Added': UsuarioSchema().dump(usuario_json)}, 200)

    def put(self, usuario_id):
        ...
    def delete(self, usuario_id):
        ...

app.add_url_rule(
    '/usuario', 
    view_func=UsuarioAPI.as_view('usuario')
    )
app.add_url_rule(
    '/usuario/<usuario_id>',
    view_func=UsuarioAPI.as_view('usuario_por_id')
    )

