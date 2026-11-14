# Registro de evidencias y demostraciones

## Evidencias principales

| Evidencia | Resultado documentado |
|---|---|
| Topología GNS3 | Router R1 + Switch SW1 + FortiGate + Cloud1 |
| Primera auditoría válida | 8 cumple, 7 no cumple, 0 errores |
| Aplicación automática | Corregidos R1 C-05, SW1 C-02/C-03/C-05, FortiGate F-01/F-03 |
| Ajuste del evaluador TLS | F-04 considera válido HTTPS administrativo con TLS 1.2 sin protocolos antiguos |
| Auditoría final | 15 cumple, 0 no cumple, 0 errores |
| Consola de R1 | HTTP y HTTPS deshabilitados; VTY con SSH y timeout |
| Consola de SW1 | HTTP y HTTPS deshabilitados; timestamps y VTY con SSH y timeout |
| Consola de FortiGate | Bloqueo 300 s, umbral 3, SSH 30 s, SSHv1 off, HTTPS TLS 1.2 |

## Registro temporal

- **17:09:41:** primer intento fallido por negociación SSH antigua / credenciales incorrectas; no es el informe de cumplimiento inicial.
- **17:13:58:** auditoría válida de partida — 8/15.
- **17:16:** aplicación de medidas; FortiGate rechazó el literal `tlsv1-3`, quedando 14/15 de acuerdo con el criterio original.
- **17:27 y 19:41:** nuevas auditorías exitosas con 15/15 para el criterio revisado.

## Conexión con el video

[Demostración de la práctica](https://youtu.be/PTBqgQA67To).

La demostración muestra el menú y el funcionamiento del script, las comprobaciones en las consolas de Cisco/FortiGate y la comparación de los resultados.

## Precisión del alcance

El parámetro global `admin-telnet enable` se observó en el FortiGate, pero su interfaz `port1` tiene `allowaccess ping https ssh`, sin Telnet. Este aspecto no forma parte de los 15 controles auditados. También aparece `ssl-min-proto-version SSLv3`, distinto del ajuste de HTTPS administrativo `admin-https-ssl-versions tlsv1-2`. Se documenta lo observado sin presentarlo como una auditoría total del equipo.