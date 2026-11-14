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
El usuario SSH usado en el laboratorio es `oliver`. No se publican contraseñas ni hashes.

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

En el menú del script: opción **1** para solo auditar; opción **2** para respaldar, corregir y auditar de nuevo. No es necesario aplicar el hardening otra vez para demostrar los resultados que ya constan en los informes.