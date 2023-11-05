from app import db
from sqlalchemy import ForeignKey, event
from sqlalchemy.orm import relationship, DeclarativeBase
from werkzeug.security import (
    generate_password_hash,
)
from datetime import datetime


class Usuario(db.Model):
    __tablename__ = 'usuario'
    id = db.Column(db.Integer, primary_key = True)
    nombre = db.Column(db.String(100), nullable = False)
    correo = db.Column(db.String(100), nullable = True, unique = True)
    password = db.Column(db.String(500), nullable = False)
    is_admin = db.Column(db.Boolean, default = False)
    fecha_creacion = db.Column(db.DateTime, 
                      nullable = False, 
                      default = datetime.utcnow)
    posts = db.relationship('Post', cascade = 'all, delete')

    def __str__(self):
        return self.name

post_tags = db.Table('post_tags',
    db.Column('post_id', 
              db.Integer, 
              db.ForeignKey('post.id'), 
              primary_key=True),
    db.Column('tag_id', 
              db.Integer, 
              db.ForeignKey('tag.id'), 
              primary_key=True)
    ) 

class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key = True)
    titulo = db.Column(db.String(100), nullable = False)
    contenido = db.Column(db.String(100), nullable = False)
    fecha = db.Column(db.DateTime, 
                      nullable = False, 
                      default = datetime.utcnow)
    usuario_id = db.Column(db.Integer, 
                           ForeignKey('usuario.id'), 
                           nullable = False)
    usuario_obj = db.relationship('Usuario', viewonly=True)
    tags = db.relationship('Tag', 
                           secondary = post_tags,
                           cascade = 'all, delete')
    comentarios = db.relationship('Comentario', cascade = 'all, delete')
    
    def __str__(self):
        return self.name

class Tag(db.Model):
    __tablename__ = 'tag'
    id = db.Column(db.Integer, primary_key = True)
    nombre = db.Column(db.String(100), nullable = False, unique = True)

    def __str__(self):
        return self.name


class Comentario(db.Model):
    __tablename__ = 'comentario'
    id = db.Column(db.Integer, primary_key = True)
    post_id = db.Column(db.Integer, 
                        ForeignKey('post.id'),
                        nullable = False)
    contenido = db.Column(db.String(100), nullable = False)
    fecha = db.Column(db.DateTime, 
                      nullable = False, 
                      default = datetime.utcnow)
    usuario_id = db.Column(db.Integer, 
                           ForeignKey('usuario.id'), 
                           nullable = False)
    usuario_obj = db.relationship('Usuario')

    def __str__(self):
        return self.name
