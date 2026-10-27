/*
   Mihari Threat Research - SleekRat Android RAT
   Reporte: https://mihari-intelligence.blogspot.com/2026/10/sleekrat-android-rat-adb-wireless.html
   Muestra de referencia (APK):
     SHA-256 A83A84A14654EB52EB29B26CC1D899C42B21B99140C9E8F0E0840BAFE35FAB74
   TLP:CLEAR - CC BY 4.0

   Nota de uso: dentro de un APK, classes.dex y assets/ suelen ir comprimidos (deflate),
   por lo que las cadenas no son visibles en el fichero .apk tal cual. Para detecciones
   fiables, escanea el APK descomprimido (unzip -d) con las reglas DEX y ELF.
   La regla APK solo dispara cuando las entradas se almacenan sin comprimir.
*/

rule Android_SleekRat_APK
{
    meta:
        author      = "Mihari Threat Research"
        date        = "2026-10-13"
        description = "SleekRat Android RAT con escalada via ADB inalambrico (APK con entradas sin comprimir)"
        reference   = "https://mihari-intelligence.blogspot.com/2026/10/sleekrat-android-rat-adb-wireless.html"
        hash        = "A83A84A14654EB52EB29B26CC1D899C42B21B99140C9E8F0E0840BAFE35FAB74"
        tlp         = "CLEAR"

    strings:
        $s1  = "com.sleekrat.accessibility.IPC_COMMAND" ascii
        $s2  = "com.sleekrat.accessibility.START_STREAM" ascii
        $s3  = "com.sleekrat.accessibility.KEYLOG_EVENT" ascii
        $s4  = "com.sleekrat.action.KEEP_ALIVE" ascii
        $s5  = "/data/local/tmp/sleekratd" ascii
        $s6  = "sleekrat_watchdog.sh" ascii
        $s7  = "SleekRatNetwork" ascii
        $s8  = "AdbPairingClient" ascii
        $s9  = "AdbSpake2" ascii
        $s10 = "setprop persist.adb.tcp.port 5555" ascii

    condition:
        uint32(0) == 0x04034b50 and          // ZIP magic (APK)
        6 of ($s*)
}

rule Android_SleekRat_DEX
{
    meta:
        author      = "Mihari Threat Research"
        date        = "2026-10-27"
        description = "classes.dex de SleekRat: broadcasts com.sleekrat.*, pila ADB propia y tags de logcat"
        reference   = "https://mihari-intelligence.blogspot.com/2026/10/sleekrat-android-rat-adb-wireless.html"
        hash        = "A83A84A14654EB52EB29B26CC1D899C42B21B99140C9E8F0E0840BAFE35FAB74"
        tlp         = "CLEAR"
        validation  = "Sintaxis compilada; pendiente de prueba contra el classes.dex de referencia"

    strings:
        $b1 = "com.sleekrat.accessibility.IPC_COMMAND" ascii
        $b2 = "com.sleekrat.accessibility.UNLOCK_MONITOR_START" ascii
        $b3 = "com.sleekrat.accessibility.MASK_ENABLE" ascii
        $b4 = "com.sleekrat.accessibility.RULES_SYNC" ascii
        $b5 = "com.sleekrat.action.WAKEUP_CORE" ascii
        $t1 = "SleekRatNetwork" ascii
        $t2 = "SleekRatAccessibility" ascii
        $a1 = "AdbSpake2" ascii
        $a2 = "AdbPairingClient" ascii
        $a3 = "AdbAutoSetupPipeline" ascii
        $a4 = "AdbWirelessEnabler" ascii
        $d1 = "/data/local/tmp/sleekratd.json" ascii
        $d2 = "settings put secure sleekrat_probe" ascii

    condition:
        uint32(0) == 0x0A786564 and          // "dex\n"
        filesize < 30MB and
        (
            3 of ($b*) or
            (1 of ($t*) and 2 of ($a*)) or
            (1 of ($d*) and 1 of ($a*) and 1 of ($b*))
        )
}

rule Android_SleekRat_Daemon_ELF
{
    meta:
        author      = "Mihari Threat Research"
        date        = "2026-10-27"
        description = "Daemon Go nativo de SleekRat (sleekratd-arm64 / sleekratd-armv7), sin ofuscar"
        reference   = "https://mihari-intelligence.blogspot.com/2026/10/sleekrat-android-rat-adb-wireless.html"
        tlp         = "CLEAR"
        validation  = "Sintaxis compilada; pendiente de prueba contra sleekratd-arm64 / armv7"

    strings:
        $w1 = "sleekrat_watchdog.sh" ascii
        $w2 = "SLEEKRAT_WD_VER" ascii
        $w3 = "sleekrat_watchdo[g]" ascii
        $w4 = "/data/local/tmp/sleekrat_watchdog.log" ascii
        $m1 = "main.watchdogGuardLoop" ascii
        $m2 = "main.handleShell" ascii
        $m3 = "main.heartbeatLoop" ascii
        $m4 = "main.batteryLevel" ascii
        $g1 = "github.com/gorilla/websocket" ascii

    condition:
        uint32(0) == 0x464C457F and          // ELF
        filesize < 30MB and
        $g1 and
        (2 of ($w*) or (1 of ($w*) and 2 of ($m*)))
}
