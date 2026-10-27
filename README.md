# SleekRat — RAT Android con escalada vía depuración inalámbrica ADB

**Publicado:** 2026-10-14 · **Reporte completo:** [SleekRat: Anatomía de un RAT Android](https://mihari-intelligence.blogspot.com/2026/10/sleekrat-android-rat-adb-wireless.html) · **TLP:CLEAR**

## Resumen

SleekRat es una plataforma de fraude y control remoto para Android (Kotlin + daemon nativo en Go) que obtiene privilegios del usuario `shell` (uid 2000) sin root ni exploits de kernel: tras conseguir el permiso de accesibilidad, habilita ADB por TCP, se empareja consigo misma mediante SPAKE2 con una pila ADB propia y lanza el daemon `sleekratd` desde `/data/local/tmp/`. Recolecta pantalla (streaming a 5 FPS que arranca solo un segundo después de conectar), cámara, audio, SMS, contactos, llamadas y ubicación; cuenta los puntos del PIN en la pantalla de bloqueo; pulsa automáticamente el diálogo de consentimiento de MediaProjection y ejecuta reglas de automatización de fraude con overlays de phishing que imitan WeChat y Alipay. La persistencia es triple: watchdog shell, watchdog interno y Device Owner con un observador que re-habilita la accesibilidad.

El C2 (WebSocket en `/ws`, puerto por defecto 8080) **no está embebido en el APK**: se inyecta en tiempo de ejecución desde el panel. Por responsabilidad, la dirección del panel identificado no se publica.

## Muestra

| Campo | Valor |
|---|---|
| Paquete | `com.i3163.app` |
| SHA-256 (APK) | `A83A84A14654EB52EB29B26CC1D899C42B21B99140C9E8F0E0840BAFE35FAB74` |
| Certificado | CN=SleekRat · RSA 2048 autofirmado · SHA-256 `DFC97E4B9F4735C7927D7E2A3C2ACA6DFED462A0ACFB8EA716DB2CC7148F1CB6` |
| Lenguajes | Kotlin (APK) · Go 1.21.5 (`sleekratd-arm64`, `sleekratd-armv7`) |
| VirusTotal | 0/68 motores estáticos; el sandbox Zenbox android la clasifica como `MALWARE TROJAN EVADER` |
| Familia | No catalogada públicamente. Precedente más cercano: RedHook (Group-IB, 2026) |

## Hallazgos clave

- **Escalada sin root:** `setprop persist.adb.tcp.port 5555` + emparejamiento SPAKE2 con `AdbSpake2` / `AdbPairingClient` / `AdbMdns`.
- **Auto-activación de accesibilidad** vía `settings put secure enabled_accessibility_services` con el shell obtenido.
- **54 broadcasts** únicos bajo `com.sleekrat.*` (45 acciones IPC de `AccessibilityServiceBridge`, más eventos y keep-alive); los 48 documentados en el reporte están en `iocs.csv`.
- **Builder sobre 1Panel** con un payload de inyección de comandos en `server_host` (`/opt/1panel/apps/sleek-rat-v2/android/zhurubao/mk_sh`).
- **Logs en chino simplificado** y overlays dirigidos al ecosistema de pagos chino: indicio de *targeting*, no de atribución.

## Contenido del repositorio

| Fichero | Contenido | Validación |
|---|---|---|
| [`iocs/`](iocs) | Hashes, certificado, rutas en dispositivo, broadcasts, tags de logcat. Incluye `iocs.csv`, listas por tipo (`hashes.txt`, `network.txt`, `host.txt`) y bundle STIX 2.1 | STIX validado |
| [`attack.csv`](attack.csv) | ATT&CK con columna de revisión | Ver nota abajo |
| [`yara/sleekrat_android.yar`](yara/sleekrat_android.yar) | APK, `classes.dex` y daemon ELF | Compilan. Las reglas DEX y ELF son nuevas y están pendientes de prueba contra los ficheros extraídos |
| [`sigma/sleekrat_internal_broadcast.yml`](sigma/sleekrat_internal_broadcast.yml) | Broadcasts `com.sleekrat.*` | Logsource no estándar: requiere pipeline propio |
| [`suricata/sleekrat_android.rules`](suricata/sleekrat_android.rules) | Handshake WebSocket a `/ws` en claro | Hunting; solo `ws://` sin TLS |

### Cambios respecto a las reglas del blog

- **YARA:** se añadieron `Android_SleekRat_DEX` y `Android_SleekRat_Daemon_ELF`. La regla original sobre el APK busca cadenas que, en un APK normal, están dentro de entradas comprimidas con deflate; solo dispara si las entradas van sin comprimir. Para detección fiable hay que escanear el APK descomprimido.
- **Sigma:** UUID real en lugar del placeholder `1a2b3c4d-…`, fecha en formato ISO y nota sobre la logsource.
- **Suricata:** regla en una sola línea (Suricata no admite reglas multilínea sin `\`), URI exacta `/ws` con `bsize:3` para reducir falsos positivos, `rev:2`.
- **ATT&CK:** la tabla del blog mezcla IDs de Enterprise con la matriz Mobile. `attack.csv` conserva el mapeo publicado y marca con `review` cada ID de Enterprise junto a su candidato Mobile para su revisión.

## Atribución

Sin atribución a familia ni actor. Similitudes con RedHook (Group-IB, julio 2026) y RatHat (Zimperium, septiembre 2026) en el abuso de ADB inalámbrico, y con ClayRat (Zimperium, 2025) en accesibilidad y overlays. El indicador de actor del panel (contacto de Telegram) se documenta solo en el blog y no se incluye en los feeds, porque no es accionable.

## Referencias

- Group-IB — [RedHook Returns with a Dangerous Upgrade](https://www.group-ib.com/blog/redhook-android-rat-upgraded/)
- Zimperium — [RatHat](https://zimperium.com/blog/rathat-ai-powered-mobile-threat-is-here-for-your-credentials-bank-accounts)
- NVD — [CVE-2024-34352](https://nvd.nist.gov/vuln/detail/CVE-2024-34352) · [CVE-2025-56413](https://nvd.nist.gov/vuln/detail/CVE-2025-56413) (1Panel)

## Licencia

Reglas, IOCs y documentación bajo [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); código bajo MIT. Ver [LICENSE](LICENSE).

---

**Mihari Threat Research** · [Blog](https://mihari-intelligence.blogspot.com/) · [mihari-intelligence.com](https://mihari-intelligence.com) · TLP:CLEAR
Este repositorio no contiene muestras de malware, solo hashes.
