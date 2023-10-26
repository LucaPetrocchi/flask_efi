from app import db
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

class Usuario(db.Model):
    __tablename__ = 'usuario'
    id = db.Column(db.Integer, primary_key = True)
    nombre = db.Column(db.String(100), nullable = False)
    correo = db.Column(db.String(100), nullable = True)
    password = db.Column(db.String(100), nullable = False)
    is_admin = db.Column(db.Boolean, default = False)

class Tag(db.Model):
    __tablename__ = 'tag'
    id = db.Column(db.Integer, primary_key = True)
    nombre = db.Column(db.String(100), nullable = False)
    # relationship aca?? por si quiero que el TagSchema
    # muestre todos los posts con este tag

post_tags = db.Table('post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
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
    tags = db.relationship('tag', secondary=post_tags, backref='posts')

class Comentario(db.Model):
    __tablename__ = 'comentario'
    id = db.Column(db.Integer, primary_key = True)
    contenido = db.Column(db.String(100), nullable = False)
    fecha = db.Column(db.DateTime, 
                      nullable = False, 
                      default = datetime.utcnow)
    usuario_id = db.Column(db.Integer, 
                           ForeignKey('usuario.id'), 
                           nullable = False)



