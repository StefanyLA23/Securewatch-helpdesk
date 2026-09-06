CREATE DATABASE IF NOT EXISTS helpdesk_db;
USE helpdesk_db;

CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    rol ENUM('usuario', 'tecnico', 'admin') NOT NULL DEFAULT 'usuario',
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE categorias (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    sla_horas INT NOT NULL
);

CREATE TABLE tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    titulo VARCHAR(200) NOT NULL,
    descripcion TEXT NOT NULL,
    categoria_id INT NOT NULL,
    prioridad ENUM('baja', 'media', 'alta', 'critica') NOT NULL DEFAULT 'media',
    estado ENUM('abierto', 'en_proceso', 'escalado', 'resuelto', 'cerrado') NOT NULL DEFAULT 'abierto',
    usuario_id INT NOT NULL,
    tecnico_id INT NULL,
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    fecha_limite_sla DATETIME NULL,
    fecha_cierre DATETIME NULL,
    FOREIGN KEY (categoria_id) REFERENCES categorias(id),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
    FOREIGN KEY (tecnico_id) REFERENCES usuarios(id)
);

CREATE TABLE comentarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    usuario_id INT NOT NULL,
    contenido TEXT NOT NULL,
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

CREATE TABLE auditoria (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    usuario_id INT NOT NULL,
    accion VARCHAR(255) NOT NULL,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

INSERT INTO categorias (nombre, sla_horas) VALUES
('Phishing', 4),
('Malware', 4),
('Acceso no autorizado', 2),
('Fallo de hardware', 24),
('Fallo de software', 24),
('Solicitud general', 48),
('Vulnerabilidad', 4);

CREATE TABLE activos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(150) NOT NULL,
    tipo ENUM('servidor', 'equipo', 'software') NOT NULL,
    producto VARCHAR(150) NOT NULL,
    version VARCHAR(50) NOT NULL,
    responsable_id INT NOT NULL,
    fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (responsable_id) REFERENCES usuarios(id)
);

CREATE TABLE vulnerabilidades_detectadas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    activo_id INT NOT NULL,
    cve_id VARCHAR(30) NOT NULL,
    descripcion TEXT,
    cvss_score DECIMAL(3,1),
    fecha_deteccion DATETIME DEFAULT CURRENT_TIMESTAMP,
    ticket_id INT NULL,
    FOREIGN KEY (activo_id) REFERENCES activos(id),
    FOREIGN KEY (ticket_id) REFERENCES tickets(id),
    UNIQUE KEY activo_cve_unico (activo_id, cve_id)
);
