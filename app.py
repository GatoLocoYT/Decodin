from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    url_for,
    flash,
    session,
)
from werkzeug.utils import secure_filename
from io import BytesIO
import os
import base64
import binascii
import uuid
import mysql.connector
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)

# ---------------- CONFIGURACIÓN GENERAL ----------------

app = Flask(__name__)
app.secret_key = "clave_super_secreta"
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["DECODED_FOLDER"] = "decoded"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["DECODED_FOLDER"], exist_ok=True)

bcrypt = Bcrypt(app)

# ---------------- CONEXIÓN A LA BASE DE DATOS ----------------

db = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME"),
    port=int(os.getenv("DB_PORT", 3306))
)
cursor = db.cursor(dictionary=True)

# ---------------- FLASK-LOGIN ----------------

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password


@login_manager.user_loader
def load_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        return User(user_data["id"], user_data["username"], user_data["password"])
    return None


# ---------------- FUNCIONES DE DECODIFICACIÓN ----------------


def detectar_y_decodificar(contenido):
    contenido = contenido.strip().replace("\n", "").replace(" ", "")

    bases = {
        "Base64": base64.b64decode,
        "Base32": base64.b32decode,
        "Base16": base64.b16decode,
        "Base85": base64.b85decode,
    }

    for nombre_base, funcion in bases.items():
        try:
            decodificado = funcion(contenido)
            return decodificado, nombre_base
        except binascii.Error:
            continue
        except Exception:
            continue

    raise ValueError("No se pudo detectar una codificación válida.")


def detectar_extension(data_bytes):
    if data_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    elif data_bytes.startswith(b"mdp\x00"):
        return ".mdp"
    else:
        return ".bin"


# ---------------- RUTAS PRINCIPALES ----------------


@app.route("/", methods=["GET", "POST"])
def index():
    mensaje = None
    archivo_descargable = None

    # Limpiar archivo anterior si quedó uno
    archivo_anterior = session.pop("archivo_generado", None)
    if archivo_anterior:
        ruta = os.path.join(app.config["DECODED_FOLDER"], archivo_anterior)
        if os.path.exists(ruta):
            os.remove(ruta)

    if request.method == "POST":
        archivo = request.files.get("archivo")

        if not archivo or archivo.filename == "":
            mensaje = "No se seleccionó ningún archivo."
            return render_template("index.html", mensaje=mensaje)

        try:
            contenido = archivo.read().decode("utf-8", errors="ignore")
            datos_decodificados, base_detectada = detectar_y_decodificar(contenido)
            extension = detectar_extension(datos_decodificados)

            nombre_archivo = f"{uuid.uuid4().hex}{extension}"
            ruta_salida = os.path.join(app.config["DECODED_FOLDER"], nombre_archivo)

            with open(ruta_salida, "wb") as f:
                f.write(datos_decodificados)

            mensaje = (
                f"Archivo decodificado correctamente (detectado: {base_detectada})."
            )
            archivo_descargable = nombre_archivo
            session["archivo_generado"] = nombre_archivo

            # ✅ Si el usuario está logueado, guardar en historial
            if current_user.is_authenticated:
                cursor.execute(
                    """
                    INSERT INTO historial (
                        user_id, original_filename, detected_encoding, output_extension, archivo_generado
                    ) VALUES (%s, %s, %s, %s, %s)
                """,
                    (
                        current_user.id,
                        archivo.filename,
                        base_detectada,
                        extension,
                        nombre_archivo,
                    ),
                )
                db.commit()

        except ValueError as e:
            mensaje = f"Error: {str(e)}"
        except Exception as e:
            mensaje = f"Ocurrió un error inesperado: {str(e)}"

        return render_template(
            "index.html", mensaje=mensaje, archivo_descargable=archivo_descargable
        )

    return render_template("index.html")


@app.route("/descargar/<nombre>")
@login_required
def descargar(nombre):
    ruta = os.path.join(app.config["DECODED_FOLDER"], nombre)
    if os.path.exists(ruta):
        return send_file(ruta, as_attachment=True)
    return "Archivo no encontrado", 404


# ---------------- LOGIN Y SESIÓN ----------------


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Obtener campos del formulario con .get() para evitar KeyError
        username = request.form.get("usuario")
        password = request.form.get("password")

        if not username or not password:
            flash("Por favor, completá todos los campos", "warning")
            return redirect(url_for("login"))

        # Buscar usuario en la base de datos
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        # Validar existencia y contraseña
        if user and bcrypt.check_password_hash(user["password"], password):
            user_obj = User(user["id"], user["username"], user["password"])
            login_user(user_obj)
            return redirect(url_for("index"))
        else:
            flash("Usuario y/o contraseña incorrecta", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("index"))


# ---------------- REGISTRO DE USUARIOS ----------------
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm = request.form["confirm"]

        if password != confirm:
            flash("Las contraseñas no coinciden", "danger")
            return redirect(url_for("registro"))

        # Verificamos si ya existe el usuario
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existente = cursor.fetchone()
        if existente:
            flash("El usuario ya existe", "warning")
            return redirect(url_for("registro"))

        # Encriptamos la contraseña
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Insertamos el usuario
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hashed_password),
        )
        db.commit()

        flash("Usuario registrado con éxito, ahora podés iniciar sesión", "success")
        return redirect(url_for("login"))

    return render_template("registro.html")


# ---------------- Historial ----------------
@app.route("/historial")
@login_required
def historial():
    cursor.execute(
        """
        SELECT id, original_filename, detected_encoding, output_extension, fecha, archivo_generado
        FROM historial
        WHERE user_id = %s
        ORDER BY fecha DESC
        LIMIT 8
        """,
        (current_user.id,),
    )
    archivos = cursor.fetchall()
    return render_template("historial.html", archivos=archivos)


# ---------------- ELIMINAR ----------------
@app.route("/eliminar/<int:id>", methods=["POST"])
@login_required
def eliminar(id):
    # Primero buscamos el archivo para verificar si es del usuario logueado
    cursor.execute(
        "SELECT archivo_generado FROM historial WHERE id = %s AND user_id = %s",
        (id, current_user.id),
    )
    archivo = cursor.fetchone()

    if archivo:
        # Eliminamos el archivo físico si existe
        ruta = os.path.join(app.config["DECODED_FOLDER"], archivo["archivo_generado"])
        if os.path.exists(ruta):
            os.remove(ruta)

        # Borramos de la base de datos
        cursor.execute("DELETE FROM historial WHERE id = %s", (id,))
        db.commit()

        flash("Archivo eliminado del historial", "success")
    else:
        flash("No se encontró el archivo o no tienes permisos", "danger")

    return redirect(url_for("historial"))


# ---------------- INICIO ----------------

if __name__ == "__main__":
    app.run(debug=True)
