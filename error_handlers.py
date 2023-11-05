from flask import (
    jsonify,
    render_template,
)
from app import app

class UnauthorizedError(Exception):
    codigo = 401
    descripcion = "No Autorizado"

class APIAuthError(Exception):
    codigo = 403
    descripcion = "Error de Autenticación"

class NotFoundError(Exception):
    codigo = 404
    descripcion = "No Encontrado"

class ConflictError(Exception):
    codigo = 409
    descripcion = "La data enviada no puede ser aceptada por un conflicto"

@app.errorhandler(404)
def server_error(err):
    return "Ruta no existe"

@app.errorhandler(Exception)
def api_error(err):
    response = {
        "error": err.descripcion,
    }

    if err.args:
        response["mensaje"] = err.args[0]
    
    return jsonify(response), err.codigo

