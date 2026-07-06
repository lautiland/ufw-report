# ufw-report

CLI escrita en Rust que lee los logs de UFW, analiza trafico bloqueado y presenta un reporte interactivo en terminal (TUI). Tambien permite exportar a CSV/JSON.

## Que es

`ufw-report` resuelve el problema de interpretar los logs crudos de UFW (`/var/log/ufw.log`), que suelen ser ruidosos y dificiles de analizar con herramientas como `grep` o `tail`. A diferencia de soluciones pesadas como ELK o Splunk, esta herramienta es ligera, offline y funciona directamente en la terminal via SSH, ideal para servidores pequenos, VPS o Raspberry Pi.

## Instalacion

```bash
git clone https://github.com/tu-usuario/ufw-report.git
cd ufw-report
cargo build --release
```

El binario estara en `target/release/ufw-report`.

## Uso

```bash
# Modo TUI interactivo (default: ultimos 7 dias)
ufw-report

# Especificar rango de fechas
ufw-report --from 2026-06-01 --to 2026-06-30

# Ruta personalizada al log
ufw-report --log-file /var/log/ufw.log

# Exportar a CSV
ufw-report --csv -o reporte.csv

# Exportar a JSON (pipeable)
ufw-report -o -
```

## Funcionalidades

- Parseo de logs UFW (IPv4 e IPv6)
- Normalizacion de protocolos (numero a nombre)
- Deteccion de direccion (IN=/OUT=)
- Rango de fechas configurable (default: ultimos 7 dias)
- Dias sin datos rellenados con ceros
- Cache JSON opcional del parser
- 4 vistas: Overview, Daily, Hourly y Raw
- Exportacion a CSV y JSON

## Tests

```bash
cargo test
```

## Licencia

MIT - Copyright (c) 2026 Lautaro Matias Jovanovics
