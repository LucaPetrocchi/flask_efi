# API Foro

Este repositorio es un proyecto EFI para Python y DevOps. Utiliza Flask, MySQL y Docker para construir una API de un sistema de foros, usando los métodos de petición HTTP (GET, POST, PUT, DELETE) para ofrecer funcionalidad CRUD sobre una base de datos.

La aplicación utiliza;
* **WERKZEUG** para la creación de hashes de contraseñas,
* **JWTMANAGER** para la implementación de un sistema de permisos de tokens,
* **SQLALCHEMY** para la creación y CRUD de base de datos,
* **MIGRATE** para el manejo de migraciones a la base de datos,
* **MARSHMALLOW** para la serialización de datos desde y a JSON,
* y **DOTENV** para la creación de variables de entorno.

# Requisitos

* Python (v. 3.9 Alpine o superior)
* Docker, así como docker-compose
* Archivo .env (véase .env.example)

# Uso

## Docker

1. Clonar repositorio.
2. Ejecutar `docker-compose up -d` desde la carpeta del proyecto (requerirá sudo).
3. Una vez satisfecho, usar `docker-compose down` para detener y eliminar el contenedor.

## Manual

1. Clonar repositorio.
2. Editar .env para utilizar localhost (véase .env.example)
3. Con un servidor abierto en localhost (e.j. XAMPP), correr los siguientes comandos desde la carpeta del proyecto.

~~~
python3 venv -m venv

source venv/bin/activate [LINUX]

venv/Scripts/activate [WINDOWS]

pip install -r requirements.txt

flask db init

flask db migrate -m "init"

flask db upgrade

flask run
~~~

# Endpoints y ejemplos

Nota: Utilícese solo rutas `/usuario` O `/usuario/1`; `/usuario/` (con la segunda barra pero sin número) causará un error.

## /login

### POST

Requiere request JSON, e.j:

~~~
{
    "nombre": "admin"
    "password": "123"
}
~~~

Retorna un token de autenticación. Inclúyase como bearer en su request.

(El usuario admin tiene permisos administrativos y se crea por defecto al inicializar la aplicación.)

## /usuario/<\id>

## GET

Requiere de token de autenticación. El comportamiento de este método varía en función de los permisos del usuario; de ser administrador, incluirá información extra (permisos, hash de contraseña, fecha de creación).

De incluirse ID, buscará un usuario específico. De lo contrario, buscará todos los usuarios en la base de datos.

Retornará JSON.

## POST

~~~
{
  "nombre": "nombre",
  "correo": "mail@gmail.com",
  "password": "123",
  "is_admin": "false"
}
~~~

`"is_admin": "true` intentará crear un usuario nuevo con permisos administrativos. Esto causará que la API solicite los permisos del usuario actual mediante un token de autenticación.

## PUT

Sólo puede usarse al incluir una ID de usuario (`/usuario/1`).

Requiere JSON idéntico a POST. La request tendrá éxito de estar ausentes cualquiera de sus campos; los campos vacíos no se actualizarán en la base de datos.

Cambiar `is_admin` tendrá un comportamiento idéntico al descrito en GET.

## DELETE

Sólo puede usarse al incluir una ID de usuario (`/usuario/1`).

Requiere de token de autenticación administrativo.

Retornará JSON con la información del usuario borrado.

## /tag/<\id>

Toda esta ruta requiere token de autenticación administrativa.

### GET

De incluirse ID, buscará un tag específico. De lo contrario, buscará todos los tags en la base de datos.

Retornará JSON.

### POST

~~~
{
    "nombre": "tag"
}
~~~

### PUT

Sólo puede usarse al incluir una ID de tag (`/tag/1`).

Requiere JSON idéntico a POST. La request tendrá éxito de estar ausentes cualquiera de sus campos; los campos vacíos no se actualizarán en la base de datos.

### DELETE

Sólo puede usarse al incluir una ID de tag (`/tag/1`).

Retornará JSON con la información del tag borrado.

## /post/<\id>

### GET

De incluirse ID, buscará un post específico. De lo contrario, buscará todos los posts en la base de datos.

Retornará JSON.

### POST

~~~
{
  "titulo": "título",
  "contenido": "texto cualquiera",
  "tags": [1, 2],
  "usuario_id": 1
}
~~~

`tags` acepta solo una lista de IDs. 

### PUT

Sólo puede usarse al incluir una ID de post (`/usuario/1`).

Requiere JSON idéntico a POST. La request tendrá éxito de estar ausentes cualquiera de sus campos; los campos vacíos no se actualizarán en la base de datos.

### DELETE

Sólo puede usarse al incluir una ID de post (`/usuario/1`).

Retornará JSON con la información del tag borrado.

## /comentario/<\id>

### GET

De incluirse ID, buscará un comentario específico. De lo contrario, buscará todos los comentarios en la base de datos.

Retornará JSON.

### POST

~~~
{
  "post_id": 1,
  "contenido": "respuesta",
  "usuario_id": 2
}
~~~

### PUT

Sólo puede usarse al incluir una ID de comentario (`/comentario/1`).

Requiere JSON idéntico a POST. La request tendrá éxito de estar ausentes cualquiera de sus campos; los campos vacíos no se actualizarán en la base de datos.

### DELETE

Sólo puede usarse al incluir una ID de comentario (`/comentario/1`).

Retornará JSON con la información del comentario borrado.
