from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import (
    login_user, logout_user, login_required, current_user
)
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

from config import Config
from database import db, login_manager
from models import Usuario, Categoria, Ticket, Comentario, Auditoria, Activo
from jobs.vuln_scanner import escanear_activos

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


def registrar_auditoria(ticket_id, accion):
    entrada = Auditoria(ticket_id=ticket_id, usuario_id=current_user.id, accion=accion)
    db.session.add(entrada)


# 1. AUTENTICACION

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form["nombre"]
        email = request.form["email"]
        password = request.form["password"]

        if Usuario.query.filter_by(email=email).first():
            flash("Ese correo ya está registrado")
            return redirect(url_for("register"))

        usuario = Usuario(nombre=nombre, email=email, rol="usuario")
        usuario.set_password(password)
        db.session.add(usuario)
        db.session.commit()
        flash("Cuenta creada, inicia sesión")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario and usuario.check_password(password):
            login_user(usuario)
            return redirect(url_for("dashboard"))

        flash("Credenciales inválidas")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# 2. DASHBOARD Y LISTADO

@app.route("/")
@login_required
def dashboard():
    if current_user.rol == "usuario":
        tickets = Ticket.query.filter_by(usuario_id=current_user.id).all()
    elif current_user.rol == "tecnico":
        tickets = Ticket.query.filter(
            (Ticket.tecnico_id == current_user.id) | (Ticket.tecnico_id.is_(None))
        ).all()
    else:
        tickets = Ticket.query.all()

    total = len(tickets)
    abiertos = len([t for t in tickets if t.estado == "abierto"])
    vencidos = len([t for t in tickets if t.sla_vencido()])

    return render_template(
        "dashboard.html", tickets=tickets, total=total, abiertos=abiertos, vencidos=vencidos
    )


# 3. CREACION DE TICKETS CON TRIAGE AUTOMATICO

PALABRAS_CRITICAS = ["ransomware", "brecha", "fuga de datos", "acceso root comprometido"]
PALABRAS_ALTAS = ["phishing", "malware", "acceso no autorizado", "virus"]


def clasificar_prioridad(texto):
    texto = texto.lower()
    if any(p in texto for p in PALABRAS_CRITICAS):
        return "critica"
    if any(p in texto for p in PALABRAS_ALTAS):
        return "alta"
    return "media"


@app.route("/tickets/nuevo", methods=["GET", "POST"])
@login_required
def nuevo_ticket():
    categorias = Categoria.query.all()

    if request.method == "POST":
        titulo = request.form["titulo"]
        descripcion = request.form["descripcion"]
        categoria_id = request.form["categoria_id"]

        prioridad = clasificar_prioridad(titulo + " " + descripcion)

        ticket = Ticket(
            titulo=titulo,
            descripcion=descripcion,
            categoria_id=categoria_id,
            prioridad=prioridad,
            usuario_id=current_user.id,
        )
        ticket.calcular_sla()
        db.session.add(ticket)
        db.session.flush()
        registrar_auditoria(ticket.id, f"Ticket creado con prioridad {prioridad}")
        db.session.commit()

        flash(f"Ticket creado con prioridad: {prioridad}")
        return redirect(url_for("dashboard"))

    return render_template("ticket_form.html", categorias=categorias)


# 4. DETALLE, ASIGNACION Y CAMBIO DE ESTADO

@app.route("/tickets/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def detalle_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if request.method == "POST":
        accion = request.form.get("accion")

        if accion == "tomar" and current_user.rol in ("tecnico", "admin"):
            ticket.tecnico_id = current_user.id
            ticket.estado = "en_proceso"
            registrar_auditoria(ticket.id, f"Ticket tomado por {current_user.nombre}")

        elif accion == "escalar" and current_user.rol in ("tecnico", "admin"):
            ticket.estado = "escalado"
            registrar_auditoria(ticket.id, "Ticket escalado")

        elif accion == "resolver" and current_user.rol in ("tecnico", "admin"):
            ticket.estado = "resuelto"
            ticket.fecha_cierre = datetime.utcnow()
            registrar_auditoria(ticket.id, "Ticket resuelto")

        elif accion == "cerrar" and current_user.rol in ("usuario", "admin"):
            ticket.estado = "cerrado"
            registrar_auditoria(ticket.id, "Ticket cerrado")

        elif accion == "comentar":
            contenido = request.form["contenido"]
            comentario = Comentario(
                ticket_id=ticket.id, usuario_id=current_user.id, contenido=contenido
            )
            db.session.add(comentario)
            registrar_auditoria(ticket.id, "Comentario agregado")

        db.session.commit()
        return redirect(url_for("detalle_ticket", ticket_id=ticket.id))

    historial = Auditoria.query.filter_by(ticket_id=ticket.id).order_by(Auditoria.fecha).all()
    return render_template("ticket_detail.html", ticket=ticket, historial=historial)


# 5. INVENTARIO DE ACTIVOS

@app.route("/activos")
@login_required
def lista_activos():
    activos = Activo.query.all()
    return render_template("activos_list.html", activos=activos)


@app.route("/activos/nuevo", methods=["GET", "POST"])
@login_required
def nuevo_activo():
    if request.method == "POST":
        activo = Activo(
            nombre=request.form["nombre"],
            tipo=request.form["tipo"],
            producto=request.form["producto"],
            version=request.form["version"],
            responsable_id=current_user.id,
        )
        db.session.add(activo)
        db.session.commit()
        flash("Activo registrado")
        return redirect(url_for("lista_activos"))

    return render_template("activo_form.html")


# 6. ESCANEO DE VULNERABILIDADES

@app.route("/activos/escanear", methods=["POST"])
@login_required
def escanear_ahora():
    if current_user.rol not in ("tecnico", "admin"):
        flash("No tienes permiso para ejecutar el escaneo")
        return redirect(url_for("lista_activos"))

    with app.app_context():
        nuevos = escanear_activos(usuario_sistema_id=current_user.id)

    flash(f"Escaneo completado. Tickets nuevos generados: {nuevos}")
    return redirect(url_for("dashboard"))


def escaneo_programado():
    with app.app_context():
        admin = Usuario.query.filter_by(rol="admin").first()
        if admin:
            escanear_activos(usuario_sistema_id=admin.id)


scheduler = BackgroundScheduler()
scheduler.add_job(escaneo_programado, "interval", hours=24)
scheduler.start()


if __name__ == "__main__":
    app.run(debug=True)
