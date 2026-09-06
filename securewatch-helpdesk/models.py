from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from database import db


class Usuario(db.Model, UserMixin):
    __tablename__ = "usuarios"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.Enum("usuario", "tecnico", "admin"), default="usuario")
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Categoria(db.Model):
    __tablename__ = "categorias"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    sla_horas = db.Column(db.Integer, nullable=False)


class Ticket(db.Model):
    __tablename__ = "tickets"

    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(200), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    categoria_id = db.Column(db.Integer, db.ForeignKey("categorias.id"), nullable=False)
    prioridad = db.Column(db.Enum("baja", "media", "alta", "critica"), default="media")
    estado = db.Column(
        db.Enum("abierto", "en_proceso", "escalado", "resuelto", "cerrado"),
        default="abierto",
    )
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    tecnico_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=True)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    fecha_actualizacion = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    fecha_limite_sla = db.Column(db.DateTime, nullable=True)
    fecha_cierre = db.Column(db.DateTime, nullable=True)

    categoria = db.relationship("Categoria")
    creador = db.relationship("Usuario", foreign_keys=[usuario_id])
    tecnico = db.relationship("Usuario", foreign_keys=[tecnico_id])
    comentarios = db.relationship("Comentario", backref="ticket", cascade="all, delete-orphan")

    def calcular_sla(self):
        horas = self.categoria.sla_horas
        multiplicador = {"critica": 0.25, "alta": 0.5, "media": 1, "baja": 1.5}
        horas_ajustadas = horas * multiplicador.get(self.prioridad, 1)
        self.fecha_limite_sla = datetime.utcnow() + timedelta(hours=horas_ajustadas)

    def sla_vencido(self):
        if self.fecha_limite_sla and self.estado not in ("resuelto", "cerrado"):
            return datetime.utcnow() > self.fecha_limite_sla
        return False


class Comentario(db.Model):
    __tablename__ = "comentarios"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id"), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    contenido = db.Column(db.Text, nullable=False)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)

    usuario = db.relationship("Usuario")


class Activo(db.Model):
    __tablename__ = "activos"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)
    tipo = db.Column(db.Enum("servidor", "equipo", "software"), nullable=False)
    producto = db.Column(db.String(150), nullable=False)
    version = db.Column(db.String(50), nullable=False)
    responsable_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    fecha_registro = db.Column(db.DateTime, default=datetime.utcnow)

    responsable = db.relationship("Usuario")
    vulnerabilidades = db.relationship("VulnerabilidadDetectada", backref="activo")


class VulnerabilidadDetectada(db.Model):
    __tablename__ = "vulnerabilidades_detectadas"

    id = db.Column(db.Integer, primary_key=True)
    activo_id = db.Column(db.Integer, db.ForeignKey("activos.id"), nullable=False)
    cve_id = db.Column(db.String(30), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    cvss_score = db.Column(db.Numeric(3, 1), nullable=True)
    fecha_deteccion = db.Column(db.DateTime, default=datetime.utcnow)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id"), nullable=True)

    ticket = db.relationship("Ticket")


class Auditoria(db.Model):
    __tablename__ = "auditoria"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id"), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    accion = db.Column(db.String(255), nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
