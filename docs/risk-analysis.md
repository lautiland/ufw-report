### **Planilla de Riesgos para `ufw-report`**
Aquí tienes la planilla de riesgos reestructurada en formato de lista anidada para facilitar su lectura:

### **Riesgo 1: Ruptura del parser por cambios en el formato de log**
* **Categoría:** Técnico
* **Descripción:** Ruptura del parser por cambios en el formato del log de UFW.
* **Causas:** Actualizaciones mayores del kernel de Linux, netfilter o UFW que modifiquen la sintaxis de syslog.
* **Consecuencias:** El TUI muestra datos vacíos, erróneos o la aplicación hace *panic* al no poder hacer match con las Regex.
* **Probabilidad:** Baja
* **Impacto:** Crítico
* **Umbral (Trigger):** Reporte de *Issue* en GitHub de usuarios con Ubuntu >= 26.04.
* **Plan de Respuesta (Mitigación):** Mantener una suite de tests robusta con muestras de logs de múltiples versiones de distribuciones.
* **Plan de Contingencia:** Lanzar un *hotfix* degradando gracefully: alertar al usuario del formato desconocido en lugar de crashear.
* **Observaciones:** El riesgo aumenta si se añaden distribuciones no basadas en Debian.


### **Riesgo 2: Congelamiento de la TUI (UI Freeze)**
* **Categoría:** Rendimiento
* **Descripción:** Congelamiento de la TUI al procesar archivos masivos.
* **Causas:** El archivo `ufw.log` tiene un tamaño excesivo (ej. > 5GB) debido a un ataque DoS sostenido.
* **Consecuencias:** El hilo principal se bloquea, la interfaz no responde a comandos (`Ctrl+C`), obligando al usuario a matar el proceso.
* **Probabilidad:** Media
* **Impacto:** Alto
* **Umbral (Trigger):** Tiempo de respuesta de la TUI superior a 2 segundos al cambiar de pestaña.
* **Plan de Respuesta (Mitigación):** Implementar procesamiento asíncrono o multihilo separando el motor de parseo del renderizado TUI.
* **Plan de Contingencia:** Limitar la lectura por defecto a los últimos 500MB del archivo y requerir un flag explícito para lectura total.
* **Observaciones:** Fundamental dado el perfil técnico de SysAdmins exigentes.


### **Riesgo 3: Falsos positivos en el motor de heurística**
* **Categoría:** Seguridad / Funcional
* **Descripción:** Falsos positivos en la detección de amenazas.
* **Causas:** Parámetros del Risk Score mal calibrados; tráfico normal de la red interna es etiquetado como "Ataque Crítico".
* **Consecuencias:** Pérdida de confianza del usuario en la herramienta; fatiga de alertas que anula el propósito del dashboard.
* **Probabilidad:** Alta
* **Impacto:** Medio
* **Umbral (Trigger):** Más de 3 reportes en la comunidad indicando detecciones erróneas en tráfico local.
* **Plan de Respuesta (Mitigación):** Proveer archivos de configuración `.toml` para que el usuario calibre los umbrales de peso heurístico a su entorno.
* **Plan de Contingencia:** Desactivar temporalmente etiquetas críticas por defecto hasta ajustar el algoritmo localmente.
* **Observaciones:** El *fingerprinting* estático es propenso a errores en redes complejas.


### **Riesgo 4: Fallos de ejecución por incompatibilidad de librerías (`glibc`)**
* **Categoría:** Distribución
* **Descripción:** Fallos de ejecución por falta de dependencias del sistema operativo.
* **Causas:** Compilación dinámica estándar en Rust ejecutada en servidores corporativos con versiones de Linux muy antiguas (ej. CentOS 7).
* **Consecuencias:** Error "version `GLIBC_2.XX` not found" al intentar ejecutar el binario, bloqueando la adopción.
* **Probabilidad:** Media
* **Impacto:** Alto
* **Umbral (Trigger):** Reportes de fallo de binarios descargados desde las *Releases* de GitHub.
* **Plan de Respuesta (Mitigación):** Configurar el CI (GitHub Actions) para compilar versiones estáticas usando `x86_64-unknown-linux-musl`.
* **Plan de Contingencia:** Documentar claramente el proceso para que los usuarios compilen desde el código fuente con `cargo build`.
* **Observaciones:** Clave para despliegues *air-gapped* que no se pueden actualizar fácilmente.
