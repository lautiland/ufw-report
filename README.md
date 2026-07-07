# ufw-report

CLI escrita en Rust que lee los logs de UFW, analiza trafico bloqueado y presenta un reporte interactivo en terminal (TUI). Tambien permite exportar a CSV/JSON.

## Que es

`ufw-report` resuelve el problema de interpretar los logs crudos de UFW (`/var/log/ufw.log`), que suelen ser ruidosos y dificiles de analizar con herramientas como `grep` o `tail`. A diferencia de soluciones pesadas como ELK o Splunk, esta herramienta es ligera, offline y funciona directamente en la terminal via SSH, ideal para servidores pequenos, VPS o Raspberry Pi.

## Instalacion

```bash
git clone https://github.com/lautiland/ufw-report.git
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

## Estructura del proyecto

```
src/
├── config/             # Configuracion CLI y argumentos
│   ├── app_config.rs   #   Struct CliArgs (clap) y AppConfig
│   └── mod.rs
├── domain/             # Modelos de dominio
│   ├── entry.rs        #   LogEntry, Direction
│   ├── reports.rs      #   DailyReport, HourBreak, IpEntry, PortEntry
│   ├── aggregation.rs  #   AggregatedData, build_aggregated
│   └── mod.rs
├── output/             # Exportacion de datos
│   ├── csv.rs          #   Escritura CSV
│   ├── json.rs         #   Escritura JSON + write_output
│   └── mod.rs
├── parser/             # Parseo de logs UFW
│   ├── date_utils.rs   #   Utilidades de fecha y normalizacion
│   ├── line.rs         #   Regex y parseo de lineas individuales
│   ├── reports.rs      #   Construccion de reportes diarios
│   ├── range.rs        #   Parseo por rango de fechas + cache
│   └── mod.rs
├── tui/                # Interfaz de terminal
│   ├── app.rs          #   Estado de la aplicacion
│   ├── events.rs       #   Manejo de teclado
│   ├── header.rs       #   Barra de tabs
│   ├── status.rs       #   Barra de estado
│   ├── overview.rs     #   Vista Overview
│   ├── daily.rs        #   Vista Daily
│   ├── hourly.rs       #   Vista Hourly
│   ├── raw.rs          #   Vista Raw
│   └── mod.rs
├── error.rs            # Tipos de error (UfwError)
├── lib.rs              # Declaracion de modulos publicos
└── main.rs             # Punto de entrada
```

## Tests

```bash
cargo test
```

## Licencia

MIT - Copyright (c) 2026 Lautaro Matias Jovanovics
