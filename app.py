import os

from flask import Flask
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
ma = Marshmallow(app)

load_dotenv()

from views.views import *
# esto es para que flask migrate encuentre los modelos, borrar luego

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5005', debug=True)