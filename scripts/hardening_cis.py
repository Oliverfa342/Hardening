#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Laboratorio ITLA: auditoria y hardening de R1, SW1 y FortiGate.

Requisitos: Python 3.9+ y netmiko 4.x (probado en estructura para Netmiko 4.8).
Solo para dispositivos de laboratorio propios o administrados con autorizacion.
Los controles se inspiran en practicas de hardening de CIS; cotejar IDs
normativos exactos con el Benchmark CIS de cada version antes de documentarlos.

Opcion 1: NO modifica dispositivos.
Opcion 2: respaldo local -> auditoria previa -> aplicar reglas -> informe posterior.
No publica contrasenas, no modifica las IP ni el transporte SSH.
"""

import getpass
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from netmiko import ConnectHandler
except ImportError:
    print("Falta Netmiko. En PowerShell: py -m pip install netmiko")
    sys.exit(1)


EQUIPOS = [
    {"nombre": "R1", "host": "10.15.71.1", "tipo": "cisco_ios", "familia": "cisco", "vty": "0 4"},
    {"nombre": "SW1", "host": "10.15.71.2", "tipo": "cisco_ios", "familia": "cisco", "vty": "0 15"},
    {"nombre": "FortiGate", "host": "10.15.71.3", "tipo": "fortinet", "familia": "fortinet"},
]

REGLAS_CISCO = [
    ("C-01", "Registros con fecha/hora y milisegundos", "service timestamps log datetime msec"),
    ("C-02", "Servicio HTTP administrativo deshabilitado", "no ip http server"),
    ("C-03", "Servicio HTTPS Cisco no requerido deshabilitado", "no ip http secure-server"),
    ("C-04", "Acceso VTY solamente por SSH", "transport input ssh"),
    ("C-05", "Inactividad de VTY: maximo 5 minutos", "exec-timeout 5 0"),
]
REGLAS_FORTI = [
    ("F-01", "Bloqueo administrativo durante 300 segundos", "set admin-lockout-duration 300"),
    ("F-02", "Maximo 3 intentos de login fallidos", "set admin-lockout-threshold 3"),
    ("F-03", "Gracia de autenticacion SSH de 30 segundos", "set admin-ssh-grace-time 30"),
    ("F-04", "Administracion HTTPS: no admitir versiones inferiores a TLS 1.2", "set admin-https-ssl-versions tlsv1-2"),
    ("F-05", "SSH v1 deshabilitado", "set admin-ssh-v1 disable"),
]

RAIZ = Path(__file__).resolve().parent
SALIDAS = RAIZ / "informes_hardening"
RESPALDOS = SALIDAS / "respaldos_privados_NO_SUBIR"


def sello() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def redactar_config(texto: str) -> str:
    """Ofusca lineas frecuentes con secretos antes de crear una copia compartible."""
    patrones = [
        r"(?im)^(\s*enable\s+(?:secret|password)\s+).*$",
        r"(?im)^(\s*username\s+\S+\s+.*?\s+(?:secret|password)\s+).*$",
        r"(?im)^(\s*snmp-server\s+community\s+).*$",
        r"(?im)^(\s*password\s+).*$",
        r"(?im)^(\s*tacacs-server\s+key\s+).*$",
        r"(?im)^(\s*radius-server\s+key\s+).*$",
    ]
    for patron in patrones:
        texto = re.sub(patron, r"\1[REDACTADO]", texto)
    return texto


def conectar(equipo: dict, claves: Dict[str, str]):
    if equipo["familia"] == "cisco":
        return ConnectHandler(
            device_type=equipo["tipo"], host=equipo["host"],
            username=claves["cisco_user"], password=claves["cisco_pass"],
            conn_timeout=12, auth_timeout=14, banner_timeout=16,
            read_timeout_override=70,
            fast_cli=False,
        )
    return ConnectHandler(
        device_type=equipo["tipo"], host=equipo["host"],
        username=claves["forti_user"], password=claves["forti_pass"],
        conn_timeout=12, auth_timeout=14, banner_timeout=16,
        read_timeout_override=70,
        fast_cli=False,
    )


def secciones_vty(config: str) -> List[str]:
    # Cada bloque `line vty` comienza en columna 1; las opciones estan indentadas.
    bloques = re.findall(r"(?ms)^line vty\s+\d+\s+\d+\s*\n((?:[ \t]+[^\n]*\n)*)", config)
    return bloques


def tiene_linea(config: str, linea: str) -> bool:
    return bool(re.search(r"(?m)^\s*" + re.escape(linea) + r"\s*$", config))


def evaluar_cisco(config: str, estado_http: str, nombre: str) -> List[dict]:
    bloques = secciones_vty(config)
    estampas = bool(re.search(r"(?m)^service timestamps log datetime msec(?:\s|$)", config))
    salida = []
    for codigo, descripcion, esperado in REGLAS_CISCO:
        if codigo == "C-01":
            cumple = estampas
            evidencia = "service timestamps log datetime msec" if estampas else "No figura en running-config"
        elif codigo == "C-02":
            if re.search(r"(?im)^\s*HTTP server status:\s*Disabled", estado_http):
                cumple = True
                evidencia = "show ip http server status: Disabled"
            elif re.search(r"(?im)^\s*HTTP server status:\s*Enabled", estado_http):
                cumple = False
                evidencia = "show ip http server status: Enabled"
            else:
                cumple = tiene_linea(config, "no ip http server")
                evidencia = "no ip http server explicito" if cumple else "No se pudo confirmar el estado de HTTP (revisar manualmente)"
        elif codigo == "C-03":
            if re.search(r"(?im)^\s*HTTP secure server status:\s*Disabled", estado_http):
                cumple = True
                evidencia = "show ip http server status: HTTPS Disabled"
            elif re.search(r"(?im)^\s*HTTP secure server status:\s*Enabled", estado_http):
                cumple = False
                evidencia = "show ip http server status: HTTPS Enabled"
            else:
                cumple = tiene_linea(config, "no ip http secure-server")
                evidencia = "no ip http secure-server explicito" if cumple else "No se pudo confirmar el estado de HTTPS (revisar manualmente)"
        elif codigo == "C-04":
            cumple = len(bloques) > 0 and all(tiene_linea(b, esperado) for b in bloques)
            evidencia = f"{len(bloques)} bloques VTY; SSH exclusivo: {'si' if cumple else 'no'}"
        else:
            def tiempo_vty_correcto(bloque: str) -> bool:
                match = re.search(r"(?m)^\s*exec-timeout\s+(\d+)\s+(\d+)\s*$", bloque)
                if not match:
                    return False
                minutos, segundos = map(int, match.groups())
                return segundos < 60 and 0 < minutos * 60 + segundos <= 300
            cumple = len(bloques) > 0 and all(tiempo_vty_correcto(b) for b in bloques)
            evidencia = f"{len(bloques)} bloques VTY; timeout <= 5 min: {'si' if cumple else 'no'}"
        salida.append({"equipo": nombre, "regla": codigo, "descripcion": descripcion,
                       "esperado": esperado, "estado": "CUMPLE" if cumple else "NO CUMPLE",
                       "evidencia": evidencia})
    return salida


def obtener_valor_forti(texto: str, clave: str) -> Optional[str]:
    m = re.search(r"(?m)^\s*set\s+" + re.escape(clave) + r"\s+(.+?)\s*$", texto)
    return m.group(1).strip() if m else None


def evaluar_forti(config: str, nombre: str) -> List[dict]:
    salida = []
    objetivos = {
        "F-01": ("admin-lockout-duration", "300"),
        "F-02": ("admin-lockout-threshold", "3"),
        "F-03": ("admin-ssh-grace-time", "30"),
        "F-04": ("admin-https-ssl-versions", "tlsv1-2 (tlsv1-3 opcional)"),
        "F-05": ("admin-ssh-v1", "disable"),
    }
    for codigo, descripcion, esperado in REGLAS_FORTI:
        clave, objetivo = objetivos[codigo]
        actual = obtener_valor_forti(config, clave)
        if actual is None:
            estado = "ERROR"
            evidencia = f"No se encontro {clave} en show full-configuration system global"
        elif codigo == "F-04":
            valores = set(actual.replace('"', "").split())
            estado = "CUMPLE" if valores and valores.issubset({"tlsv1-2", "tlsv1-3"}) else "NO CUMPLE"
            evidencia = f"{clave}={actual}"
        else:
            estado = "CUMPLE" if actual == objetivo else "NO CUMPLE"
            evidencia = f"{clave}={actual}"
        salida.append({"equipo": nombre, "regla": codigo, "descripcion": descripcion,
                       "esperado": esperado, "estado": estado, "evidencia": evidencia})
    return salida


def auditar_equipo(conexion, equipo: dict, ruta: Path, guardar_copia: bool) -> List[dict]:
    nombre = equipo["nombre"]
    if equipo["familia"] == "cisco":
        config = conexion.send_command("show running-config", read_timeout=75)
        if not re.search(r"(?m)^hostname\s+\S+", config):
            raise RuntimeError("No se pudo leer running-config completo: revisa privilegio de SSH")
        if guardar_copia:
            (RESPALDOS / f"{nombre}_running_config_ORIGINAL_PRIVADO.txt").write_text(config, encoding="utf-8")
        (ruta / f"{nombre}_config_SANITIZADO.txt").write_text(redactar_config(config), encoding="utf-8")
        estado_http = conexion.send_command("show ip http server status", read_timeout=30)
        return evaluar_cisco(config, estado_http, nombre)
    config = conexion.send_command("show full-configuration system global", read_timeout=85)
    if "config system global" not in config or "set admintimeout" not in config:
        raise RuntimeError("FortiGate no devolvio la configuracion global completa")
    if guardar_copia:
        (RESPALDOS / f"{nombre}_system_global_ORIGINAL_PRIVADO.txt").write_text(config, encoding="utf-8")
    (ruta / f"{nombre}_global_SANITIZADO.txt").write_text(config, encoding="utf-8")
    return evaluar_forti(config, nombre)


def guardar_informe(registros: List[dict], errores: List[str], nombre: str, carpeta: Path) -> Path:
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = {e: sum(r["estado"] == e for r in registros) for e in ["CUMPLE", "NO CUMPLE", "ERROR"]}
    contenido = [f"INFORME HARDENING - {nombre}", f"Fecha: {fecha}",
                 "Laboratorio: R1 10.15.71.1; SW1 10.15.71.2; FortiGate 10.15.71.3",
                 "Alcance: controles seleccionados para la practica; no auditoria CIS certificada.",
                 f"Resumen: {total['CUMPLE']} cumplen; {total['NO CUMPLE']} no cumplen; {total['ERROR']} error(es)", "=" * 72]
    for item in registros:
        contenido += [f"[{item['estado']}] {item['equipo']} - {item['regla']}: {item['descripcion']}",
                      f"  Objetivo: {item['esperado']}", f"  Evidencia: {item['evidencia']}", ""]
    if errores:
        contenido.extend(["ERRORES DE CONEXION O COMANDOS:"] + errores)
    contenido += ["", "AVISO: Revisar el Benchmark CIS correspondiente antes de asignar IDs normativos.",
                  "NO PUBLICAR los archivos en la carpeta respaldos_privados_NO_SUBIR."]
    carpeta.mkdir(parents=True, exist_ok=True)
    salida = carpeta / f"{nombre}.txt"
    salida.write_text("\n".join(contenido) + "\n", encoding="utf-8")
    (carpeta / f"{nombre}.json").write_text(
        json.dumps({"fecha": fecha, "resumen": total, "registros": registros, "errores": errores},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    return salida


def auditar_todos(claves: dict, carpeta: Path, respaldar: bool) -> Tuple[List[dict], List[str]]:
    registros, errores = [], []
    carpeta.mkdir(parents=True, exist_ok=True)
    if respaldar:
        RESPALDOS.mkdir(parents=True, exist_ok=True)
    for equipo in EQUIPOS:
        print(f"\n[*] Auditando {equipo['nombre']} ({equipo['host']})...")
        conexion = None
        try:
            conexion = conectar(equipo, claves)
            resultado = auditar_equipo(conexion, equipo, carpeta, respaldar)
            registros.extend(resultado)
            for fila in resultado:
                print(f"  {fila['regla']}: {fila['estado']}")
        except Exception as exc:
            mensaje = f"{equipo['nombre']} ({equipo['host']}): {type(exc).__name__}: {exc}"
            errores.append(mensaje)
            print(f"  [ERROR] {mensaje}")
        finally:
            if conexion is not None:
                try:
                    conexion.disconnect()
                except Exception:
                    pass
    return registros, errores


def aplicar_cisco(conexion, equipo: dict, incumplidas: set) -> str:
    cmd = []
    if "C-01" in incumplidas:
        cmd.append("service timestamps log datetime msec")
    if "C-02" in incumplidas:
        cmd.append("no ip http server")
    if "C-03" in incumplidas:
        cmd.append("no ip http secure-server")
    if "C-04" in incumplidas or "C-05" in incumplidas:
        cmd.append(f"line vty {equipo['vty']}")
        if "C-04" in incumplidas:
            cmd.append("transport input ssh")
        if "C-05" in incumplidas:
            cmd.append("exec-timeout 5 0")
        cmd.append("exit")
    if not cmd:
        return "Sin cambios; controles seleccionados ya cumplen."
    salida = conexion.send_config_set(cmd, read_timeout=85, error_pattern=r"(?im)^%\s*(Invalid input|Error|Incomplete command|Ambiguous command)")
    conexion.save_config()
    return salida


def aplicar_forti(conexion, incumplidas: set) -> str:
    orden = [
        ("F-01", "set admin-lockout-duration 300"),
        ("F-02", "set admin-lockout-threshold 3"),
        ("F-03", "set admin-ssh-grace-time 30"),
        ("F-04", "set admin-https-ssl-versions tlsv1-2"),
        ("F-05", "set admin-ssh-v1 disable"),
    ]
    cmd = [linea for regla, linea in orden if regla in incumplidas]
    if not cmd:
        return "Sin cambios; controles seleccionados ya cumplen."
    # El driver fortinet de Netmiko administra los prompts de subconfiguracion.
    salida = conexion.send_config_set(["config system global", *cmd, "end"],
                                     cmd_verify=False, read_timeout=85)
    if re.search(r"(?i)(command fail|parse error|unknown action|return code -\d+)", salida):
        raise RuntimeError(f"FortiGate reporto un error: {salida[-900:]}")
    return salida


def aplicar_todos(claves: dict, registros: List[dict]) -> List[str]:
    errores = []
    for equipo in EQUIPOS:
        nombre = equipo["nombre"]
        incumplidas = {fila["regla"] for fila in registros
                       if fila["equipo"] == nombre and fila["estado"] == "NO CUMPLE"}
        print(f"\n[*] Aplicando controles pendientes: {nombre} -> {', '.join(sorted(incumplidas)) or 'ninguno'}")
        if not incumplidas:
            continue
        conexion = None
        try:
            conexion = conectar(equipo, claves)
            if equipo["familia"] == "cisco":
                salida = aplicar_cisco(conexion, equipo, incumplidas)
            else:
                salida = aplicar_forti(conexion, incumplidas)
            print("  Aplicacion finalizada; revisaremos el estado en la auditoria posterior.")
            # No imprimimos configuraciones ni material potencialmente sensible.
        except Exception as exc:
            mensaje = f"{nombre}: {type(exc).__name__}: {exc}"
            errores.append(mensaje)
            print(f"  [ERROR] {mensaje}")
            print("  Revisa consola de GNS3; no se continua con cambios en este equipo.")
        finally:
            if conexion is not None:
                try:
                    conexion.disconnect()
                except Exception:
                    pass
    return errores


def pedir_claves() -> dict:
    print("\nLas contrasenas NO quedan guardadas en el script ni los informes.")
    cisco_user = input("Usuario SSH de R1 y SW1 [oliver]: ").strip() or "oliver"
    cisco_pass = getpass.getpass("Contrasena SSH Cisco (R1 y SW1): ")
    forti_user = input("Usuario SSH de FortiGate [admin]: ").strip() or "admin"
    forti_pass = getpass.getpass("Contrasena SSH FortiGate: ")
    return {"cisco_user": cisco_user, "cisco_pass": cisco_pass,
            "forti_user": forti_user, "forti_pass": forti_pass}


def main() -> None:
    print("\n" + "=" * 60)
    print("  HARDENING DE RED - CIS (CONTROLES SELECCIONADOS)")
    print("  Oliver Eliam Aquino Paulino | Matricula 2024-1571")
    print("=" * 60)
    print("1. SOLO AUDITAR (sin cambios en R1, SW1 y FortiGate)")
    print("2. RESPALDAR + AUDITAR + APLICAR + INFORME POSTERIOR")
    print("3. Salir")
    opcion = input("\nElige opcion [1/2/3]: ").strip()
    if opcion == "3":
        return
    if opcion not in ("1", "2"):
        print("Opcion no valida. No se modifica ningun equipo.")
        return
    claves = pedir_claves()
    sesion = SALIDAS / sello()
    carpeta_previa = sesion / "antes"
    datos, errores = auditar_todos(claves, carpeta_previa, respaldar=(opcion == "2"))
    informe_previo = guardar_informe(datos, errores, "informe_antes", carpeta_previa)
    print(f"\n[OK] Informe inicial: {informe_previo}")
    if opcion == "1":
        print("MODO SOLO INFORME: ningun comando de hardening fue enviado.")
        return
    if errores or any(fila["estado"] == "ERROR" for fila in datos) or len(datos) != 15:
        print("\n[DETENIDO] La auditoria inicial no se completo correctamente para todos los equipos.")
        print("No aplicamos cambios. Revisa los errores e intenta nuevamente.")
        return
    print("\nATENCION: la opcion 2 SI modifica configuraciones de R1, SW1 y FortiGate.")
    print(f"Copias iniciales guardadas en: {RESPALDOS}")
    print("Mantente con la consola GNS3 disponible para recuperacion si algo falla.")
    confirmar = input('Para continuar escribe exactamente APLICAR: ').strip()
    if confirmar != "APLICAR":
        print("Cancelado. Las configuraciones permanecen sin modificar.")
        return
    errores_aplicar = aplicar_todos(claves, datos)
    carpeta_despues = sesion / "despues"
    posteriores, errores_post = auditar_todos(claves, carpeta_despues, respaldar=False)
    informe_posterior = guardar_informe(posteriores, errores_aplicar + errores_post,
                                       "informe_despues", carpeta_despues)
    print(f"\n[OK] Informe posterior: {informe_posterior}")
    print("Compara antes/informe_antes.txt con despues/informe_despues.txt")
    if errores_aplicar or errores_post:
        print("[AVISO] Se detectaron errores: revisa el informe antes de declarar cumplimiento.")
    print("\nRECUERDA: no publiques carpetas respaldos_privados_NO_SUBIR ni claves en GitHub.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.")