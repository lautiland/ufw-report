# Plan de Implementación: Refactorización por Módulos

## Resumen Ejecutivo

Reorganizar la estructura plana actual (`src/*.rs`) en un sistema de módulos por directorios, alineado con el WBS. El objetivo es separar responsabilidades, facilitar el desarrollo futuro (motor de amenazas, TUI ampliada), y mantener la compilación y tests pasando en cada fase.

**Regla central:** los módulos se comunican a través de datos (`models/`), no a través de referencias cruzadas directas.

---

## Estructura Objetivo

```
src/
├── main.rs
├── lib.rs
├── cli/
│   ├── mod.rs
│   ├── args.rs          # CliArgs (clap)
│   └── config.rs        # AppConfig
├── core/
│   ├── mod.rs
│   ├── parser.rs        # parse_log_line(), regexes
│   ├── range.rs         # parse_ufw_log_range(), build_daily_reports()
│   └── cache.rs         # Caché JSON
├── models/
│   ├── mod.rs
│   ├── entry.rs         # LogEntry, Direction
│   ├── report.rs        # DailyReport, HourBreak, IpEntry, PortEntry
│   └── aggregate.rs     # AggregatedData, build_aggregated()
├── output/
│   ├── mod.rs
│   ├── csv.rs           # write_csv()
│   └── json.rs          # write_json(), write_output()
├── tui/
│   ├── mod.rs           # run_tui()
│   ├── app.rs           # Struct App
│   ├── tabs/
│   │   ├── mod.rs
│   │   ├── overview.rs
│   │   ├── daily.rs
│   │   ├── hourly.rs
│   │   └── raw.rs
│   └── widgets/
│       ├── mod.rs
│       └── ...
├── error.rs
└── logging.rs
```

---

## Dependencias Entre Módulos

```
main.rs → cli, core, models, output, tui
cli/    → error
core/   → models, error
models/ → (ninguno)
output/ → models
tui/    → models
```

---

## Fase 1: Reorganizar Código Existente (refactor puro)

**Objetivo:** Mover código a los nuevos directorios sin cambiar lógica.

### 1.1 Crear estructura de directorios
- `src/cli/`, `src/core/`, `src/models/`, `src/output/`, `src/tui/`
- `src/tui/tabs/`, `src/tui/widgets/`

### 1.2 Mover `config.rs` → `cli/`
- `src/config.rs` → `src/cli/config.rs` (renombrar args internamente)
- `src/cli/args.rs` → extraer `CliArgs` de `config.rs`
- Crear `src/cli/mod.rs` con re-exports

### 1.3 Mover `parser.rs` → `core/`
- Separar `parse_ufw_log_range()`, `build_daily_reports()` → `core/range.rs`
- Mover regexes y `parse_log_line()` → `core/parser.rs`
- Mover lógica de caché → `core/cache.rs`
- Crear `src/core/mod.rs` con re-exports

### 1.4 Mover `models.rs` → `models/`
- `Direction`, `LogEntry` → `models/entry.rs`
- `DailyReport`, `HourBreak`, `IpEntry`, `PortEntry` → `models/report.rs`
- `AggregatedData`, `build_aggregated()` → `models/aggregate.rs`
- Crear `src/models/mod.rs` con re-exports

### 1.5 Mover `output.rs` → `output/`
- `write_csv()` → `output/csv.rs`
- `write_json()`, `write_output()` → `output/json.rs`
- Crear `src/output/mod.rs` con re-exports

### 1.6 Mover `tui.rs` → `tui/`
- `App` struct → `tui/app.rs`
- Cada tab → `tui/tabs/{overview,daily,hourly,raw}.rs`
- Event loop y helpers → `tui/mod.rs`
- Crear `src/tui/widgets/mod.rs` (vacío por ahora)

### 1.7 Crear `logging.rs`
- Extraer setup de `tracing_subscriber` de `main.rs`

### 1.8 Actualizar `lib.rs` y `main.rs`
- `lib.rs`: re-exportar `cli`, `core`, `models`, `output`, `tui`, `error`, `logging`
- `main.rs`: actualizar imports

### 1.9 Verificar
```bash
cargo fmt
cargo clippy -D warnings
cargo test
```

---

## Fase 2: Separar TUI en Sub-componentes

**Objetivo:** Cada tab y widget reutilizable en su propio archivo.

### 2.1 Extraer tabs
- Cada función de rendering de tab → archivo independiente en `tui/tabs/`
- `tui/mod.rs` delega a cada tab según `current_tab`

### 2.2 Extraer widgets
- BarChart con windowing → `tui/widgets/bar_chart.rs`
- Tabla con scroll → `tui/widgets/table_scroll.rs`
- Tarjetas de resumen → `tui/widgets/summary_cards.rs`

### 2.3 Verificar
```bash
cargo fmt && cargo clippy -D warnings && cargo test
```

---

## Fase 3: Preparar Motor de Amenazas (stubs)

**Objetivo:** Crear la estructura del módulo `threat/` con interfaces listas.

### 3.1 Crear `src/threat/`
- `mod.rs`: trait `ThreatDetector`
- `bruteforce.rs`: stub
- `portscan.rs`: stub
- `anomaly.rs`: stub
- `scoring.rs`: stub
- `fingerprint.rs`: stub

### 3.2 Agregar `ThreatAlert` a `models/`

### 3.3 Integrar en pipeline (sin lógica real)

### 3.4 Verificar
```bash
cargo fmt && cargo clippy -D warnings && cargo test
```

---

## Verificación Final

```bash
cargo fmt --check
cargo clippy -D warnings
cargo test
```

## Criterios de Aceptación

1. [ ] Fase 1: Todos los archivos reorganizados, tests pasan
2. [ ] Fase 2: TUI separada en tabs/widgets independientes
3. [ ] Fase 3: Módulo `threat/` creado con traits e integración stub
4. [ ] `cargo clippy` sin warnings en cada fase
5. [ ] `lib.rs` re-exporta todo correctamente
