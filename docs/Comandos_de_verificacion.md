# Comandos de comprobación — Hardening

## Router R1 · Consola GNS3
```cisco
enable
terminal length 0
show running-config
show ip http server status
show running-config | section line vty
show running-config | include service timestamps log
show ip ssh
```

## Switch SW1 · Consola GNS3
```cisco
enable
terminal length 0
show running-config
show ip http server status
show running-config | section line vty
show running-config | include service timestamps log
show ip ssh
```
La autenticación SSH de Cisco utiliza el usuario local `oliver`.

## FortiGate · Consola GNS3
```text
get system status
show system global
show system interface
show full-configuration system global | grep admin-
```

## Desde Windows 11 — PowerShell
```powershell
Test-NetConnection 10.15.71.1 -Port 22
Test-NetConnection 10.15.71.2 -Port 22
Test-NetConnection 10.15.71.3 -Port 22
py -m pip install "netmiko[par4]"
py .\hardening_cis.py
```

El programa cuenta con dos modalidades: **1. Auditoría sin cambios** y **2. Respaldo, aplicación de controles y auditoría posterior**. Las pruebas se documentan en los informes del proyecto.