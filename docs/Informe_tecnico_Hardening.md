# Informe técnico — Hardening de red con Cisco IOS y FortiOS

**Estudiante:** Oliver Eliam Aquino Paulino  
**Matrícula:** 2024-1571  
**Asignatura:** Seguridad de Redes  
**Fecha:** 13 de noviembre de 2026  
**Entorno:** GNS3, Cisco 7200 IOS 15.2(4)S6, Cisco IOSvL2 15.2, FortiGate-VM FortiOS 7.0.9, Windows 11, Python y Netmiko.

## 1. Objetivo y alcance

Construir una red de laboratorio con **router, switch y firewall** y realizar una revisión automática de 15 controles de endurecimiento elegidos a partir de buenas prácticas de CIS Benchmarks. El programa ofrece el modo **solo informe** y el modo **respaldar, aplicar y auditar otra vez**.

La evaluación comprende los **15 controles seleccionados para el laboratorio**. Este conjunto no constituye una auditoría integral ni una certificación CIS. Los identificadores C-01 a C-05 y F-01 a F-05 son identificadores *internos* de esta práctica y no números oficiales de recomendaciones CIS.

## 2. Diseño y direccionamiento

| Equipo | Interfaces | Dirección | Función |
|---|---|---|---|
| R1 · Cisco 7200 | FastEthernet0/0 | 10.15.71.1/24 | Enlace a SW1, acceso SSH |
| SW1 · IOSvL2 | Vlan1 | 10.15.71.2/24 | Concentración LAN, acceso SSH |
| FortiGate · FortiOS 7.0.9 | port1 | 10.15.71.3/24 | Administración segura, acceso SSH y HTTPS |
| Windows 11 físico | VMware VMnet2 | 10.15.71.10/24 | Ejecutar auditoría con Python/Netmiko |
| LAN | — | 10.15.71.0/24 | Segmento de administración del laboratorio |

Topología: R1, FortiGate y Cloud están conectados a SW1. Cloud1 enlaza Windows 11 usando VMware VMnet2. El FortiGate **no** está situado en el camino de tráfico entre R1 y Windows: en esta práctica se evalúa su propia configuración administrativa.

## 3. Controles seleccionados, su motivo y la verificación

### Cisco R1 y SW1 — cinco comprobaciones por dispositivo

| Regla | Verificación / objetivo | Justificación |
|---|---|---|
| C-01 | `service timestamps log datetime msec` | Permite correlacionar registros y relacionar los eventos con una hora específica. |
| C-02 | `no ip http server` | Desactiva HTTP administrativo innecesario y reduce servicios expuestos. |
| C-03 | `no ip http secure-server` | Desactiva el servicio HTTPS propio de Cisco cuando no se usa para administrar estos equipos. |
| C-04 | `transport input ssh` en todos los bloques VTY | Restringe el acceso remoto a SSH en lugar de permitir Telnet. |
| C-05 | `exec-timeout 5 0` en todos los bloques VTY | Cierra sesiones administrativas abandonadas luego de cinco minutos de inactividad. |

Para verificar: `show ip http server status`, `show running-config | section line vty`, `show running-config | include service timestamps log` y auditoría del script.

### FortiGate — cinco comprobaciones

| Regla | Verificación / objetivo | Justificación |
|---|---|---|
| F-01 | `set admin-lockout-duration 300` | Retrasa nuevos intentos de autenticación tras exceder el umbral de fallos. |
| F-02 | `set admin-lockout-threshold 3` | Limita a tres intentos fallidos antes del bloqueo administrativo. |
| F-03 | `set admin-ssh-grace-time 30` | Reduce el período de autenticación de una conexión SSH no completada. |
| F-04 | `set admin-https-ssl-versions tlsv1-2` | Evita negociar TLS 1.0 o TLS 1.1 en la interfaz HTTPS administrativa. |
| F-05 | `set admin-ssh-v1 disable` | Evita la versión 1 obsoleta del protocolo SSH. |

Verificación: `show full-configuration system global | grep admin-` y evaluación automatizada de Netmiko.

## 4. Funcionamiento del programa

El archivo `scripts/hardening_cis.py` usa conexiones SSH desde el host Windows para consultar la configuración de cada uno de los tres equipos.

**Opción 1 — Solo auditar:** analiza los controles y guarda un informe; no modifica configuraciones.

**Opción 2 — Respaldar, aplicar y volver a auditar:** audita, guarda respaldos, solicita escribir `APLICAR`, envía los ajustes que falten y genera un segundo informe. Se requiere mantener acceso por consola durante el procedimiento.

Las credenciales se introducen de forma oculta durante la ejecución y no están incrustadas en el código. La prueba se ejecutó con Netmiko 4.8.0 y compatibilidad Paramiko 4 para dispositivos Cisco antiguos.

## 5. Comparación de resultados

| Equipo | Antes | Después |
|---|---:|---:|
| Router R1 | 4/5 | 5/5 |
| Switch SW1 | 2/5 | 5/5 |
| FortiGate | 2/5 | 5/5 |
| **Total** | **8/15** | **15/15** |

La auditoría inicial exitosa se realizó a las 17:13:58 del 13/11/2026. La auditoría final registrada corresponde a las 19:41:15 del mismo día.

**Validación de TLS:** el control F-04 fue marcado `NO CUMPLE` en el análisis inicial porque el primer evaluador esperaba TLS 1.2 **y** TLS 1.3. El equipo ya utilizaba TLS 1.2. Se ajustó el criterio para aceptar TLS 1.2 sin protocolos anteriores. De las siete diferencias reportadas, **seis se resolvieron cambiando configuraciones** y **una cambiando la lógica de evaluación**.

En la prueba intermedia, FortiGate rechazó el parámetro `tlsv1-3`. Se adecuó la evaluación a TLS 1.2 y se repitió la auditoría.

## 6. Evidencias y anexos

- [Auditoría inicial — 8/15](../informes/Auditoria_inicial_8_de_15.txt)
- [Auditoría final — 15/15](../informes/Auditoria_final_15_de_15.txt)
- [Código fuente de la herramienta de automatización](../scripts/hardening_cis.py)
- [Running-config completo de R1 sin recortar](../running-configs/R1_running-config_COMPLETO.txt)
- [Running-config completo de SW1 sin recortar](../running-configs/SW1_running-config_COMPLETO.txt)
- [Configuración completa del apartado `system global` de FortiGate](../running-configs/FortiGate_system_global_FULL.txt)
- [Configuración de interfaces observada en FortiGate](../running-configs/FortiGate_system_interface.txt)
- [Guía de comandos de prueba](Comandos_de_verificacion.md)

## 7. Consideraciones de seguridad

Estos son controles puntuales; la configuración global de FortiOS aún presenta parámetros fuera de esta lista. Por ejemplo, `admin-telnet enable` está presente globalmente, aunque `port1` **no permite Telnet** en `allowaccess`. Asimismo, `ssl-min-proto-version SSLv3` corresponde a otro parámetro SSL y no debe confundirse con `admin-https-ssl-versions tlsv1-2`. Esas líneas deben evaluarse por separado para no declarar el dispositivo completamente endurecido.

Los archivos de Cisco contienen la configuración completa obtenida mediante `show running-config`, incluidas las líneas de interfaces, servicios, VTY y banners. La documentación de FortiGate comprende la sección `system global` y la configuración de interfaces verificada; no abarca el resto de secciones del sistema.

## 8. Conclusión

El laboratorio demuestra el funcionamiento de una herramienta automatizada que audita tres dispositivos, corrige configuraciones y genera evidencia posterior. El total reportado pasó de 8 a 15 controles conformes para los criterios implementados; se distinguió el ajuste del evaluador TLS de los cambios efectivamente realizados en la red.