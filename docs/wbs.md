### **WBS: ufw-report (Desarrollo y Expansión)**

#### **1.0 Core Engine & Procesamiento de Datos**

*Actualmente el análisis es síncrono**. El objetivo aquí es mantener la precisión actual y preparar el motor para volúmenes masivos de datos.*

* **1.1 Parser de Logs (Estado Actual)**
* 1.1.1 Parseo de logs UFW para IPv4 e IPv6.
* 1.1.2 Normalización de protocolos (numérico a nombre).
* 1.1.3 Detección de dirección del tráfico (IN/OUT).
* 1.1.4 Sistema de caché JSON opcional.

* **1.2 Escalabilidad y Performance (Futuro)**
* 1.2.1 Refactorización a una arquitectura multihilo para el procesamiento concurrente de archivos de log masivos, evitando bloqueos en la interfaz.
* 1.2.2 Implementación de parser extendido para *flags* TCP, tamaño de ventana y TTL (necesario para fingerprinting offline).

---

#### **2.0 Motor de Heurística de Amenazas (Nuevo)**

*El núcleo de la propuesta de valor que convierte los datos en inteligencia procesable offline**.*

* **2.1 Detección de Patrones**
* 2.1.1 Módulo de detección de Fuerza Bruta (ráfagas a puertos de administración).
* 2.1.2 Módulo de detección de Port Scanning (escaneos horizontales y verticales).
* 2.1.3 Módulo de detección de volumen anómalo (posibles ataques DoS).

* **2.2 Sistema de Puntuación (Risk Score)**
* 2.2.1 Algoritmo local de asignación de pesos según la gravedad del tráfico.

* **2.3 Fingerprinting Estático**
* 2.3.1 Base de datos local (JSON/YAML) incrustada en el binario con firmas de herramientas de escaneo comunes (Nmap, Masscan).

---

#### **3.0 Interfaz TUI (Terminal User Interface)**

*Ampliando las vistas actuales para acomodar la nueva inteligencia sin sacrificar el rendimiento.*

* **3.1 Vistas y Controles (Estado Actual)**
* 3.1.1 Sistema de pestañas: Overview, Daily, Hourly y Raw.
* 3.1.2 Navegación por teclado e interacciones de scroll.

* **3.2 Dashboard de Seguridad (Futuro)**
* 3.2.1 Nueva pestaña "Threats/Alerts" ordenando IPs por el *Risk Score* calculado en lugar de solo por volumen.
* 3.2.2 Identificadores visuales (tags o colores en terminal) para el tipo de amenaza detectada directamente en las vistas "Overview" y "Raw".

* **3.3 Análisis Forense interactivo (Futuro)**
* 3.3.1 Controles TUI para aislar y hacer "zoom" en ventanas de tiempo específicas (ej. seleccionar un pico anómalo en el gráfico *Daily* y expandir el detalle de ese incidente).

---

#### **4.0 CLI & Mitigación Activa-Pasiva**

*Proveyendo soluciones de bloqueo sin que la herramienta ejecute comandos privilegiados.*

* **4.1 Argumentos y Exportación (Estado Actual)**
* 4.1.1 Manejo de fechas (`--from`, `--to`) y rutas de log.
* 4.1.2 Exportación de datos enriquecidos a CSV y JSON, incluyendo soporte para *pipelines* (`-o -`).

* **4.2 Generación de Mitigación (Futuro)**
* 4.2.1 Nuevo *flag* o atajo en la TUI para generar scripts de bloqueo (`bash` con comandos `ufw deny`) para que el usuario los ejecute de forma manual y controlada.

---

#### **5.0 Arquitectura, Calidad y Distribución**

*Garantizando la estabilidad y facilitando la adopción por parte de SysAdmins.*

* **5.1 Calidad y Seguridad Base (Estado Actual)**
* 5.1.1 Suite de 56 tests (parser, config, models).
* 5.1.2 CI Pipeline con GitHub Actions (fmt, clippy, tests).
* 5.1.3 *Panic hook* para restauración de la terminal en caso de errores.

* **5.2 Distribución (Futuro)**
* 5.2.1 Empaquetado para gestores de la comunidad (Cargo) y creación de binarios estáticos para despliegues *air-gapped*.
* 5.2.2 Creación de paquetes `.deb` o PPAs específicos para entornos Ubuntu/Debian.
