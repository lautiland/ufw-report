# Estado Actual de ufw-report

> **Versión:** 0.1.0 | **Fecha:** 2026-07-06

## Qué es

`ufw-report` es una CLI escrita en Rust que lee los logs de UFW (`/var/log/ufw.log`), analiza tráfico bloqueado en un rango de fechas y presenta un reporte interactivo en terminal (TUI). Exporta a CSV/JSON.

## Stack

Rust | ratatui + crossterm | clap | chrono | serde | regex | tracing

## Features actuales

### Parser y datos
- Parseo de logs UFW (IPv4 + IPv6)
- Normalización de protocolos (numérico → nombre)
- Detección de dirección (IN=/OUT=)
- Rango de fechas configurable (default: últimos 7 días)
- Días sin datos rellenados con ceros
- Cache JSON opcional del parser

### CLI
- `--log-file <PATH>` — ruta al log (default: `/var/log/ufw.log`)
- `--from <DATE>` / `--to <DATE>` — rango de fechas
- `--csv` — exportar CSV y salir
- `-o, --output <PATH>` — exportar JSON o CSV a archivo
- `-o -` — JSON a stdout (pipeable)
- `-v, --verbose` — logging detallado

### TUI (interfaz de terminal)
- **Overview** — 4 tarjetas de resumen (Total, Incoming, Outgoing, IPs únicas) + distribución por protocolo + Top IPs + Top Puertos
- **Daily** — gráfico de barras por día; Enter para ver desglose horario
- **Hourly** — barras por hora del día seleccionado
- **Raw** — tabla paginada con todos los registros (Fecha, Hora, Src IP, Dst IP, Puerto, Protocolo, Dirección)

## TUI Controls

| Key | Action |
|-----|--------|
| `1`-`4` | Switch tabs (Overview, Daily, Hourly, Raw) |
| `Tab` / `←` `→` | Next / previous tab |
| `↑` `↓` | Scroll in Overview or Raw tabs |
| `PgUp` `PgDn` | Fast scroll |
| `Enter` | In Daily tab: switch to Hourly view |

### Calidad
- 56 tests (parser, config, models, output)
- CI con GitHub Actions (check, clippy, test, fmt, build)
- Panic hook que restaura terminal en caso de crash

### Seguridad
- Solo lectura — no modifica reglas de firewall
- Sin dependencias de red ni servidores HTTP

### Dependencias
- clap (4): CLI parsing 
- ratatui (0.30): TUI rendering
- crossterm (0.29): Terminal rendering
- serde (1): Serialization/deserialization
- serde_json (1): JSON serialization/deserialization
- chrono (0.4): Date/time parsing
- regex (1): Regular expressions
- anyhow (1): Error handling
- thiserror (2): Error handling
- tracing (0.1): Logging
- tracing-subscriber (0.3): Logging

### Otros
- **No async.** The analysis pipeline is synchronous.
- **Parser reads the raw UFW log** every time the tool runs. Has optional JSON cache support.
- **IPv4 + IPv6 support**, protocol normalization (numeric → name via `/etc/protocols`), direction detection (IN=/OUT=).
- **Default range** = last 7 calendar days. Missing days are zero-filled.
- **CSV/JSON columns**: `date, hour, src_ip, dst_ip, src_port, dst_port, protocol, direction`
- **Terminal safety**: panic hook restores terminal on crash.
- Without `--csv` or `--output`, the tool enters TUI interactive mode.
- The TUI takes over the terminal (alternate screen). Press `q` or `Ctrl+C` to exit.
