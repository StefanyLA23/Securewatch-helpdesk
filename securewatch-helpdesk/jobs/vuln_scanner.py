import requests
from datetime import datetime, timedelta

from database import db
from models import Activo, VulnerabilidadDetectada, Ticket, Categoria

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def buscar_cves(producto, version):
    params = {"keywordSearch": f"{producto} {version}", "resultsPerPage": 10}
    respuesta = requests.get(NVD_URL, params=params, timeout=15)

    if respuesta.status_code != 200:
        return []

    datos = respuesta.json()
    resultados = []

    for item in datos.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        descripcion = cve["descriptions"][0]["value"] if cve.get("descriptions") else ""

        cvss_score = None
        metricas = cve.get("metrics", {})
        if "cvssMetricV31" in metricas:
            cvss_score = metricas["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metricas:
            cvss_score = metricas["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metricas:
            cvss_score = metricas["cvssMetricV2"][0]["cvssData"]["baseScore"]

        if cvss_score is not None:
            resultados.append(
                {"cve_id": cve_id, "descripcion": descripcion, "cvss_score": float(cvss_score)}
            )

    return resultados


def clasificar_por_cvss(score):
    if score >= 9.0:
        return "critica"
    if score >= 7.0:
        return "alta"
    if score >= 4.0:
        return "media"
    return "baja"


def crear_ticket_automatico(activo, hallazgo, categoria_vulnerabilidad, usuario_sistema_id):
    prioridad = clasificar_por_cvss(hallazgo["cvss_score"])

    ticket = Ticket(
        titulo=f"Vulnerabilidad {hallazgo['cve_id']} detectada en {activo.nombre}",
        descripcion=(
            f"Activo: {activo.nombre} ({activo.producto} {activo.version})\n"
            f"CVE: {hallazgo['cve_id']}\n"
            f"CVSS: {hallazgo['cvss_score']}\n\n"
            f"{hallazgo['descripcion']}"
        ),
        categoria_id=categoria_vulnerabilidad.id,
        prioridad=prioridad,
        usuario_id=usuario_sistema_id,
    )
    ticket.calcular_sla()
    db.session.add(ticket)
    db.session.flush()
    return ticket


def escanear_activos(usuario_sistema_id):
    categoria_vulnerabilidad = Categoria.query.filter_by(nombre="Vulnerabilidad").first()
    activos = Activo.query.all()
    nuevos_tickets = 0

    for activo in activos:
        hallazgos = buscar_cves(activo.producto, activo.version)

        for hallazgo in hallazgos:
            if hallazgo["cvss_score"] < 7.0:
                continue

            ya_existe = VulnerabilidadDetectada.query.filter_by(
                activo_id=activo.id, cve_id=hallazgo["cve_id"]
            ).first()

            if ya_existe:
                continue

            ticket = crear_ticket_automatico(
                activo, hallazgo, categoria_vulnerabilidad, usuario_sistema_id
            )

            registro = VulnerabilidadDetectada(
                activo_id=activo.id,
                cve_id=hallazgo["cve_id"],
                descripcion=hallazgo["descripcion"],
                cvss_score=hallazgo["cvss_score"],
                ticket_id=ticket.id,
            )
            db.session.add(registro)
            nuevos_tickets += 1

    db.session.commit()
    return nuevos_tickets
