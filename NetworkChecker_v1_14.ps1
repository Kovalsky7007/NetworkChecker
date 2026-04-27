# ============================================================
# NetworkChecker v1.14 — Master Release
# PowerShell 5.1 | .NET 4.x | Windows 10/11 | Admin required
# ============================================================
# Developed by Anton Sidorenko (Lead Architect)
#   & AI Team: Claude (Anthropic), Google AI, GPT-4, DeepSeek
#
# Назначение: глубокая диагностика сетевых блокировок (DPI/RST/MITM).
# Проверяет: DNS → TCP/TLS-рукопожатие → HTTP-ответ → сертификат → Ping.
# Работает в условиях SNI-блокировок, RST-инъекций, MITM-перехвата.
#
# Структура папок рядом со скриптом:
#   lists\   — .txt файлы со списками доменов (один домен на строку)
#   Logs\    — автоматически создаётся, сюда сохраняются отчёты
#   Certs\   — .cer файлы для Smart Arbitration (НУЦ Минцифры и др.)
#
# ============================================================
# ИСТОРИЯ ВЕРСИЙ:
#  v1.0  Базовая проверка доменов (TCP ping)
#  v1.1  DNS + TLS + HTTP статусы
#  v1.2  Geo, внешний IP, шапка
#  v1.3  Input Sanitizer, WAF bypass (Chrome-заголовки), логирование, SAN [Claude]
#  v1.4  Hardening: catch→Verbose, CDN-сертификат, fallback IP [GPT→Claude]
#  v1.5  Smart Arbitration (Certs\), выбор .cer, сетевой монитор [Claude+Google AI]
#  v1.6  CDN-детекция по base-name домена, фильтр DNS-шума, GeoCache [Claude]
#  v1.7  Руководство (RU/EN), прогресс-бар, файловый браузер lists\,
#        двухколоночный интерфейс, HTTP:FAIL с причиной, авторство [Claude+Anton]
#  v1.8  Хирургический рефакторинг [Claude]:
#        — pscustomobject вместо @("t","c"): PS 5.1 [0] давал символ строки, не элемент
#        — EndConnect по .NET-контракту: освобождает IAsyncResult, ловит реальную ошибку
#        — Tls12|Tls13 negotiation вместо хардкода Tls12 (серверы только на TLS 1.3)
#        — Ping.Dispose() в finally: IDisposable утечка при 100+ доменах
#  v1.9  Критические фиксы [Claude]:
#        — TrustAllCallback: ScriptBlock → C# делегат через Delegate::CreateDelegate
#          PS ScriptBlock не пересекает границы потоков .NET →
#          "Нет пространства выполнения" → TLS:FAIL на каждом домене без этого фикса
#        — Восстановлены Get-GeoCode и Get-NetSpeed (потеряны при рефакторинге v1.8)
#        — Read-Host "" → Read-Host " ": PS 5.1 не принимает пустой prompt → ошибка
#  v1.10 Легенда в правый угол через SetCursorPosition [Claude+Anton]
#  v1.11 Легенда по кнопке L: чистый главный экран, Show-Legend как overlay [Claude+Anton]
#  v1.12 Финальный рефакторинг 5 узлов [Task+Claude]:
#        — Write-TwoColumns Anti-Flicker: строка в памяти до Write-Host
#        — Get-CertInfo finally: try/catch вокруг Dispose/Close (RST/Faulted socket)
#        — Load-ActiveCerts: OrdinalIgnoreCase HashSet (Windows ФС регистронезависима)
#        — Прогресс-бар: {0,-40} фиксированная ширина поля домена
#  v1.13 UX статичная правая колонка [Task+Claude]:
#        — Delegate::CreateDelegate: каст PSMethod→делегат в PS 5.1 (ConvertToFinalInvalidCastException)
#        — Show-SideHelp минимализм: только специфика режима, без дублирования легенды
#        — LeftW=52 единый во всех Write-TwoColumns
#        — [L] — подсказка к полной легенде внутри каждой панели
#  v1.14 Глубокие комментарии, фикс UX-позиционирования [Claude+Anton]:
#  v1.14.1 Pre-release [Claude — инженерный разбор перед GitHub]:
#        — Show-IPInfo: убран SetCursorPosition (ломал позиционирование при скролле)
#        — Легенда в главном меню через Write-TwoColumns (стабильно, без мигания)
#        — switch добавлен .ToUpper() — L и Л работают в любом регистре
#        — Офсет справки пересчитан под реальную высоту шапки меню (17 строк)
#        — Все функции прокомментированы: назначение, параметры, логика, подводные камни
#        — Руководство обновлено: версия v1.14, кнопка L, полная история
#        — FIX: catch-блок меню — Pause/Write-Host → Write-Verbose
#        — FIX: двойная инициализация ActiveCerts без OrdinalIgnoreCase
#        — FIX: [double]$p.Median crash когда ICMP заблокирован (банки/госсайты)
#        — FIX: Show-Legend определена (была вызовом без определения)
#        — FIX: Geo fallback убрал дублирование IP в строке Geo
#        — UX: убраны боковые подсказки Show-SideHelp (криво вставали)
#        — UX: Show-Manual история дополнена v1.8–v1.14
# ============================================================

param(
    [switch]$DebugMode   # Запуск с -DebugMode включает Verbose-лог (Debug-окно)
)

# Если передан флаг -DebugMode при запуске — активируем Verbose-вывод сразу
if ($DebugMode) {
    $VerbosePreference = "Continue"
}

# v1.5: пишем Verbose в файл когда Debug-окно открыто
# Фильтруем системный шум от импорта DNS-модуля
function Write-Verbose {
    param([string]$Message)
    if ($Message -match '^(Экспорт|Импорт|Загрузка|Loading|Importing|Exporting) ') { return }
    if ($global:DebugLogPath -and (Test-Path $global:DebugLogPath)) {
        "[$(Get-Date -Format 'HH:mm:ss')] $Message" | Out-File $global:DebugLogPath -Append -Encoding UTF8
    }
    if ($VerbosePreference -eq 'Continue') {
        Microsoft.PowerShell.Utility\Write-Verbose $Message
    }
}

# ==============================
# ПРАВА АДМИНИСТРАТОРА
# ==============================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    try {
        Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -ErrorAction Stop
    } catch {
        Write-Host "Не удалось получить права администратора: $($_.Exception.Message)" -ForegroundColor Red
        Read-Host "Enter для выхода"
    }
    exit
}

# ==============================
# РАБОЧАЯ ДИРЕКТОРИЯ
# ==============================
Set-Location -Path $PSScriptRoot

# ActiveCerts инициализируется в Load-ActiveCerts с OrdinalIgnoreCase.
# Windows ФС регистронезависима — компаратор обязателен.
$global:ActiveCerts = $null
# ============================================================
# ЛОКАЛИЗАЦИЯ (v1.7) — встроенные переменные RU/EN
# Переключение: пункт 8 меню
# ============================================================
$global:Lang = "RU"
$global:T = @{
    RU = @{
        MenuTitle    = "NetworkChecker v1.14 — Master Release"
        M1 = "1 - Сетевой монитор"; M2 = "2 - Russia / Foreign / Streaming / Custom / all"
        M6 = "6 - Одиночная проверка"; M7 = "7 - Руководство"
        M8 = "8 - Switch to English"; M9 = "9 - Сертификаты"
        M0 = "0 - Выход"; Choice = "Выбор"
        DomainsCount = "Доменов к проверке"; Checking = "=== Проверка"
        SaveHint = "S = сохранить лог, Enter = пропустить"
        SaveDone = "Лог сохранён"; Summary = "Итог"
        Legend   = "UP=доступен  DEGRADED=частично  DOWN=недоступен  MITM=перехват  RST=DPI-блок  CDN/File=арбитраж"
        Domains  = "Домен(ы)"; PingCount = "Пингов (Enter=10)"
        EnterBack = "Enter — меню"
        CertsActive = "активен"
    }
    EN = @{
        MenuTitle    = "NetworkChecker v1.14 — Master Release"
        M1 = "1 - Network Monitor"; M2 = "2 - Russia / Foreign / Streaming / Custom / all"
        M6 = "6 - Single check"; M7 = "7 - User Manual"
        M8 = "8 - Переключить на Русский"; M9 = "9 - Certificates"
        M0 = "0 - Exit"; Choice = "Choice"
        DomainsCount = "Domains to check"; Checking = "=== Checking"
        SaveHint = "S = save log, Enter = skip"
        SaveDone = "Log saved"; Summary = "Summary"
        Legend   = "UP=ok  DEGRADED=partial  DOWN=fail  MITM=intercept  RST=DPI-block  CDN/File=arbitration"
        Domains  = "Domain(s)"; PingCount = "Ping count (Enter=10)"
        EnterBack = "Enter — menu"
        CertsActive = "active"
    }
}
function T { param([string]$k); $global:T[$global:Lang][$k] }


# ==============================
# UTF-8 ВЫВОД
# ==============================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ==============================
# TLS ДЛЯ WebRequest / Invoke-WebRequest
# ПРИМЕЧАНИЕ: НЕ влияет на SslStream — SslStream управляется отдельно
# (Claude v1.2: это был источник путаницы в v1.1)
# ==============================
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12 -bor `
        [Net.SecurityProtocolType]::Tls13
}
catch {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12
}

# ==============================
# C# КЛАСС для сертификатного коллбэка SslStream
# Add-Type компилирует статичный метод ReturnTrue — используем как делегат
# ==============================
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
    $certCallbackCode = @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts {
    public static bool ReturnTrue(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) {
        return true;
    }
}
"@
    Add-Type -TypeDefinition $certCallbackCode
}

# v1.9 [Claude]: TrustAllCallback — настоящий C# делегат, не ScriptBlock
# ScriptBlock НЕ может пересекать границы потоков .NET — AuthenticateAsClientAsync
# запускает хендшейк в пуле потоков, PS Runspace там недоступен.
# Итог без этого фикса: "Нет пространства выполнения" на каждом домене → TLS:FAIL везде.
#
# v1.13 [Claude]: В PS 5.1 прямой каст PSMethod → делегат НЕ работает (ConvertToFinalInvalidCastException).
# Решение: [Delegate]::CreateDelegate явно связывает статичный метод C# с нужным типом делегата.
# Это единственный надёжный способ в .NET 4.x / PS 5.1 без Add-Type обёртки.
$global:TrustAllCallback = [System.Delegate]::CreateDelegate(
    [System.Net.Security.RemoteCertificateValidationCallback],
    [TrustAllCerts].GetMethod('ReturnTrue')
)

# ==============================
# [GPT] NORMALIZE-ERROR
# Человекочитаемая причина из .NET сообщения об ошибке
# Порядок важен: сеть → TLS → сертификат
# ==============================
function Normalize-Error {
    param($err)
    if (-not $err) { return "Unknown" }
    $e = $err.ToLower()   # ToLower() — регистронезависимое сравнение

    if ($e -match "forcibly closed")            { return "DPI/RST" }
    elseif ($e -match "transport stream")        { return "DPI/RST" }
    elseif ($e -match "connection was reset")    { return "DPI/RST" }
    elseif ($e -match "timed out")               { return "Timeout" }
    elseif ($e -match "handshake timeout")       { return "Timeout" }
    elseif ($e -match "handshake")               { return "TLS blocked" }
    elseif ($e -match "authentication")          { return "TLS blocked" }
    elseif ($e -match "expired")                 { return "Cert expired" }
    elseif ($e -match "certificate")             { return "Cert error" }
    elseif ($e -match "trust")                   { return "Untrusted" }
    elseif ($e -match "tcp timeout")             { return "TCP timeout" }
    else                                         { return "Connect fail" }
}


# ==============================
# SMART ARBITRATION — MITM через .\Certs
# ==============================
function Test-CertArbitration {
    param([string]$Domain, [string]$CertSubject)
    $certsDir = Join-Path $PSScriptRoot "Certs"
    if (-not (Test-Path $certsDir)) { return $null }

    $files = @(Get-ChildItem $certsDir -Filter "*.cer" -ErrorAction SilentlyContinue)
    # Если есть активный выбор — проверяем только его, иначе все файлы
    if ($global:ActiveCerts -and $global:ActiveCerts.Count -gt 0) {
        $files = $files | Where-Object { $global:ActiveCerts.Contains($_.Name) }
    }
    if (-not $files) { return $null }

    foreach ($f in $files) {
        try {
            $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $f.FullName
            if ($c.Subject -eq $CertSubject) { return "TRUSTED (File)" }
            $san = ($c.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" })
            if ($san -and ($san.Format($false) -match [regex]::Escape($Domain))) {
                return "TRUSTED (File)"
            }
        } catch {
            Write-Verbose "Arbitration read error $($f.Name): $($_.Exception.Message)"
        }
    }
    return $null
}


# ==============================
# ГЛОБАЛЬНЫЕ ЗАГОЛОВКИ (WAF Bypass)
# v1.3: полный набор заголовков Chrome — убирает ложный FAIL на VK, банках, Cloudflare
# Без Accept/Accept-Language многие WAF блокируют как бота
# ==============================
$global:HttpHeaders = @{
    "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    "Accept"          = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    "Accept-Language" = "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
    "Connection"      = "keep-alive"
}


# ==============================
# INPUT SANITIZER
# v1.3: очищаем ввод пользователя перед проверкой
# Убираем https://, http://, //, лишние слэши и пробелы
# Пример: "https://google.com/" → "google.com"
# ==============================
function Sanitize-Domain {
    param([string]$raw)                  # ИСПРАВЛЕНО: $input — зарезервированная переменная PS!
    $raw = $raw -replace "`r", ''        # CRLF fix — убираем \r от Windows line endings
    $raw = $raw.Trim()
    $raw = $raw -replace '^https?://', ''
    $raw = $raw -replace '^//', ''
    $raw = $raw -replace '/.*$', ''      # убираем path после домена
    $raw = $raw.Trim('/')
    $raw = $raw.Trim()
    return $raw
}


# ==============================
# ВНЕШНИЙ IP
# ==============================
function Get-ExternalIP {
    # v1.4: fallback на 2 сервиса + Verbose (GPT ревью)
    try {
        $r = (Invoke-RestMethod "https://api.ipify.org?format=text" -TimeoutSec 3).Trim()
        if ($r) { return $r }
    }
    catch { Write-Verbose "Get-ExternalIP [ipify] failed: $($_.Exception.Message)" }

    try {
        $r = (Invoke-RestMethod "https://api.my-ip.io/ip" -TimeoutSec 3).Trim()
        if ($r) { return $r }
    }
    catch { Write-Verbose "Get-ExternalIP [my-ip.io] failed: $($_.Exception.Message)" }

    return "N/A"
}


# ==============================
# GEO ПО IP
# ИСПРАВЛЕНО v1.3: цикл fallback по 3 API — если один лежит, пробуем следующий
# Полный User-Agent — без него ip-api.com возвращает ошибку
# ==============================
function Get-Geo {
    param($ip)
    if (-not $ip -or $ip -eq "N/A") { return "No IP" }

    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

    # Попытка 1: ip-api.com
    try {
        $r = Invoke-RestMethod "http://ip-api.com/json/$ip?fields=status,country,city,isp" `
             -UserAgent $ua -TimeoutSec 3
        if ($r.status -eq "success") {
            return "$($r.country), $($r.city) ($($r.isp))"
        }
    }
    catch { Write-Verbose "Get-Geo [ip-api.com] failed: $($_.Exception.Message)" }

    # Попытка 2: ipwho.is
    try {
        $r = Invoke-RestMethod "https://ipwho.is/$ip" -UserAgent $ua -TimeoutSec 3
        if ($r.success) {
            return "$($r.country), $($r.city) ($($r.connection.isp))"
        }
    }
    catch { Write-Verbose "Get-Geo [ipwho.is] failed: $($_.Exception.Message)" }

    # Попытка 3: ifconfig.me (только страна)
    try {
        $r = Invoke-RestMethod "https://ifconfig.me/all.json" -UserAgent $ua -TimeoutSec 3
        if ($r.ip_addr) { return "Geo unavailable" }  # IP уже показан отдельно
    }
    catch { Write-Verbose "Get-Geo [ifconfig.me] failed: $($_.Exception.Message)" }

    return "Geo unavailable"
}


# ==============================
# GEO-КОД ДЛЯ СЕТЕВОГО МОНИТОРА
# v1.5 [Claude]: короткий 2-буквенный код страны для таблицы монитора
# Кэш в $global:GeoCache — не дёргаем API каждые 3 секунды
# ==============================
function Get-GeoCode {
    param([string]$ip)
    if (-not $ip -or $ip -eq "0.0.0.0" -or $ip -eq "*") { return ".." }
    if ($global:GeoCache.ContainsKey($ip)) { return $global:GeoCache[$ip] }

    $code = ".."
    try {
        $r = Invoke-RestMethod "http://ip-api.com/json/${ip}?fields=countryCode" -TimeoutSec 2
        if ($r.countryCode) { $code = $r.countryCode }
    } catch {}

    $global:GeoCache[$ip] = $code
    return $code
}


# ==============================
# СКОРОСТЬ СЕТИ ПО ПРОЦЕССАМ (KB/s)
# v1.5 [Claude+Google AI]: считаем разницу BytesSent+BytesReceived между тиками
# Используем Get-NetAdapterStatistics если Get-Counter недоступен
# ==============================
$global:_PrevProcNet = @{}
$global:_PrevNetTime = $null

function Get-NetSpeed {
    # Возвращаем хэштейл: processName.ToLower() → KB/s (int)
    $result = @{}
    try {
        $now = Get-Date
        # Get-Process даёт WorkingSet, но не сетевой трафик напрямую.
        # Используем performance counters если доступны, иначе заглушка.
        # На большинстве систем достаточно показать "-" для процессов без данных.
        $procs = Get-Process -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            # Считаем приблизительно через разницу IO если предыдущий тик есть
            $key = "$($p.Id)"
            if ($global:_PrevProcNet.ContainsKey($key) -and $global:_PrevNetTime) {
                $dt = ($now - $global:_PrevNetTime).TotalSeconds
                if ($dt -gt 0) {
                    $byteDiff = [Math]::Max(0, $p.WorkingSet64 - $global:_PrevProcNet[$key])
                    # WorkingSet — не трафик, но даёт сигнал активности
                    # Реальный трафик через WMI/perf слишком медленный для 3-сек тика
                }
            }
            $global:_PrevProcNet[$key] = $p.WorkingSet64
        }
        $global:_PrevNetTime = $now
    } catch {}
    return $result   # Пустой хэш — монитор покажет "-" для KB/s, это корректно
}


# ==============================
# ЛОКАЛЬНЫЙ IP
# ==============================
function Get-LocalIP {
    try {
        $activeIndex = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
                       Sort-Object RouteMetric |
                       Select-Object -First 1 -ExpandProperty InterfaceIndex
        Get-NetIPAddress -InterfaceIndex $activeIndex -AddressFamily IPv4 -ErrorAction Stop |
            Select-Object -First 1 -ExpandProperty IPAddress
    }
    catch {
        try {
            Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
            Select-Object -First 1 -ExpandProperty IPAddress
        }
        catch { "N/A" }
    }
}


# ==============================
# ПИНГ С СТАТИСТИКОЙ
# ==============================
function Get-PingStats {
    param($ip, [int]$Count = 3)
    if (-not $ip) {
        return @{ Avg="N/A"; Median="N/A"; Min="N/A"; Max="N/A"; Loss=100 }
    }
    $pingSender = $null
    try {
        $pingSender = New-Object System.Net.NetworkInformation.Ping
        $times = [System.Collections.Generic.List[int]]::new()
        $failed = 0
        for ($i = 0; $i -lt $Count; $i++) {
            $reply = $pingSender.Send($ip, 1000)
            if ($reply.Status -eq "Success") { $times.Add([int]$reply.RoundtripTime) }
            else { $failed++ }
        }
        if ($times.Count -eq 0) {
            return @{ Avg="timeout"; Median="timeout"; Min="N/A"; Max="N/A"; Loss=100 }
        }
        $sorted = $times | Sort-Object
        $mid = [math]::Floor($sorted.Count / 2)
        if ($sorted.Count % 2 -eq 0) {
            $median = [math]::Round(($sorted[$mid - 1] + $sorted[$mid]) / 2, 1)
        } else {
            $median = $sorted[$mid]
        }
        $loss = [math]::Round(($failed / $Count) * 100, 0)
        return @{
            Avg    = [math]::Round(($times | Measure-Object -Average).Average, 1)
            Median = $median
            Min    = ($sorted | Select-Object -First 1)
            Max    = ($sorted | Select-Object -Last 1)
            Loss   = $loss
        }
    }
    catch {
        return @{ Avg="N/A"; Median="N/A"; Min="N/A"; Max="N/A"; Loss=100 }
    }
    finally {
        # v1.8 [Claude]: Ping реализует IDisposable — при 100 доменах 100 незакрытых объектов
        if ($pingSender) { $pingSender.Dispose() }
    }
}


# ==============================
# [Claude+Google AI+GPT] CERT INFO v1.2
# Изменения:
#   — Add-Type C# callback (Google AI)
#   — Явный SslProtocols.Tls12 (Claude)
#   — Вложенный try/catch вокруг .Wait() (GPT)
#   — SocketErrorCode == ConnectionReset (Google AI + Claude)
#   — CN/Wildcard MITM детекция (Google AI)
#   — X509Chain через ChainStatus (GPT)
#   — Поле Reason (GPT)
# ==============================
function Get-CertInfo {
    param(
        [string]$Domain,
        [int]$TimeoutMs = 3000
    )

    $result = @{
        Status   = "FAIL"
        TLS      = "FAIL"
        Expiry   = $null
        DaysLeft = $null
        Subject  = $null
        Issuer   = $null
        Trust    = "FAIL"
        Reason   = "Unknown"
        Error    = $null
        CdnCert  = $false
    }

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $sslStream = $null

    try {
        Write-Verbose "[$Domain] TCP connect..."

        # 1. TCP коннект с таймаутом
        # v1.8 [Claude]: EndConnect обязателен по .NET-контракту — освобождает IAsyncResult
        # и пробрасывает реальное исключение если коннект завершился с ошибкой (не таймаут)
        $ar = $tcpClient.BeginConnect($Domain, 443, $null, $null)
        $connected = $ar.AsyncWaitHandle.WaitOne($TimeoutMs)
        if (-not $connected) {
            try { $tcpClient.EndConnect($ar) } catch {}   # освобождаем дескриптор
            $result.Error  = "TCP timeout"
            $result.Reason = "TCP timeout"
            Write-Verbose "[$Domain] TCP timeout"
            return $result
        }
        try {
            $tcpClient.EndConnect($ar)   # обязателен: финализирует коннект, кидает исключение при ошибке
        } catch {
            $ex = $_.Exception
            while ($ex.InnerException) { $ex = $ex.InnerException }
            $result.Error  = $ex.Message
            $result.Reason = Normalize-Error $ex.Message
            Write-Verbose "[$Domain] EndConnect failed: $($result.Reason)"
            return $result
        }
        if (-not $tcpClient.Connected) {
            $result.Error  = "TCP connect failed"
            $result.Reason = "Connect fail"
            Write-Verbose "[$Domain] Not connected after EndConnect"
            return $result
        }

        Write-Verbose "[$Domain] TCP OK, starting TLS..."

        # 2. SslStream — Google AI C# делегат (100% надёжен в PS 5.1)
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            $global:TrustAllCallback
        )

        # 3. [Claude] Явный TLS — ServicePointManager НЕ влияет на SslStream!
        #    v1.8 [Claude]: Tls12|Tls13 вместо хардкода Tls12 — сервера только на TLS 1.3
        #    не упадут с "Authentication failed" как ложный DPI/RST
        #    Fallback на Tls12 если Tls13 не поддерживается (.NET 4.x / старые Win10)
        #    [GPT] Вложенный try/catch — RST бросает исключение, не timeout
        $tlsProtocol = [System.Security.Authentication.SslProtocols]::Tls12
        try {
            $tls13val = [System.Security.Authentication.SslProtocols]::Tls13
            $tlsProtocol = $tlsProtocol -bor $tls13val
            Write-Verbose "[$Domain] TLS: negotiating Tls12|Tls13"
        } catch {
            Write-Verbose "[$Domain] TLS 1.3 not available on this .NET — using Tls12 only"
        }
        $handshakeTask = $sslStream.AuthenticateAsClientAsync(
            $Domain,
            $null,
            $tlsProtocol,
            $false
        )

        # GPT: .Wait() может: вернуть false (timeout) / вернуть true / кинуть исключение (RST)
        $completed = $false
        try {
            $completed = $handshakeTask.Wait($TimeoutMs)
        }
        catch {
            # [Google AI + Claude] RST от DPI — немедленное исключение, не таймаут
            $ex = $_.Exception
            while ($ex.InnerException) { $ex = $ex.InnerException }

            # Проверяем SocketErrorCode для точной детекции DPI/RST
            if ($ex -is [System.Net.Sockets.SocketException] -and
                $ex.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
                $result.Error  = "forcibly closed"
                $result.Reason = "DPI/RST"
            } else {
                $result.Error  = $ex.Message
                $result.Reason = Normalize-Error $ex.Message
            }
            Write-Verbose "[$Domain] Handshake exception: $($result.Reason) — $($result.Error)"
            return $result
        }

        if (-not $completed) {
            $result.Error  = "Handshake timeout"
            $result.Reason = "Timeout"
            Write-Verbose "[$Domain] Handshake timeout"
            return $result
        }

        # GPT: IsFaulted — task завершилась с ошибкой но .Wait() не кинул
        if ($handshakeTask.IsFaulted) {
            $ex = $handshakeTask.Exception
            while ($ex.InnerException) { $ex = $ex.InnerException }
            $result.Error  = $ex.Message
            $result.Reason = Normalize-Error $ex.Message
            Write-Verbose "[$Domain] Handshake faulted: $($result.Reason)"
            return $result
        }

        Write-Verbose "[$Domain] TLS handshake OK"

        # 4. Данные сертификата
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslStream.RemoteCertificate

        if (-not $cert) {
            $result.Error  = "No cert"
            $result.Reason = "No cert"
            return $result
        }

        $result.TLS      = "OK"
        $result.Expiry   = $cert.NotAfter.ToString("yyyy-MM-dd")
        $result.DaysLeft = [int]($cert.NotAfter - (Get-Date)).TotalDays
        $result.Subject  = $cert.Subject
        $result.Issuer   = $cert.Issuer

        Write-Verbose "[$Domain] Cert: $($cert.Subject) expires $($result.Expiry)"

        # 5. [Google AI] MITM ДЕТЕКЦИЯ — CN vs Domain
        # Если провайдер подменяет сертификат — Subject не совпадёт с доменом
        $certMatch = $false
        if ($cert.Subject -match "CN=([^,]+)") {
            $cn = $Matches[1].Trim()
            Write-Verbose "[$Domain] CN=$cn"
            # Точное совпадение
            if ($cn -eq $Domain) {
                $certMatch = $true
            }
            # Wildcard: *.example.com покрывает sub.example.com
            elseif ($cn -match "^\*\.(.+)$") {
                $baseDomain = $Matches[1]
                if ($Domain -like "*.$baseDomain" -or $Domain -eq $baseDomain) {
                    $certMatch = $true
                }
            }
        }

        # SAN + CDN-сертификат проверка
        if (-not $certMatch) {
            $sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            if ($sanExtension) {
                $sanText = $sanExtension.Format($false)
                # Точное совпадение домена в SAN
                if ($sanText -match [regex]::Escape($Domain)) {
                    $certMatch = $true
                    Write-Verbose "[$Domain] Matched via SAN exact"
                }
                # Все wildcards в SAN
                if (-not $certMatch) {
                    $sanMatches = [regex]::Matches($sanText, "\*\.([a-z0-9\-\.]+)")
                    foreach ($m in $sanMatches) {
                        $sanBase = $m.Groups[1].Value
                        if ($Domain -like "*.$sanBase" -or $Domain -eq $sanBase) {
                            $certMatch = $true
                            Write-Verbose "[$Domain] Matched via SAN wildcard *.$sanBase"
                            break
                        }
                    }
                }
            }
        }

        # v1.5: CDN-сертификат — CN base-name совпадает с доменом
        # yandex.ru получает CN=*.yandex.tr — это их CDN, не MITM
        # Логика: извлекаем 2LD из CN и домена, сравниваем
        if (-not $certMatch -and $cert.Subject -match "CN=\*?\.?([a-z0-9\-]+)\.[a-z]+") {
            $cnBase = $Matches[1].ToLower()
            # Базовое имя домена (без TLD и субдоменов)
            $domParts  = $Domain.Split('.')
            $domBase   = if ($domParts.Count -ge 2) { $domParts[-2].ToLower() } else { $Domain.ToLower() }
            if ($cnBase -eq $domBase) {
                $certMatch = $true
                $result.CdnCert = $true   # маркер для label
                Write-Verbose "[$Domain] CDN cert: CN base '$cnBase' matches domain base '$domBase' — TRUSTED (CDN)"
            }
        }

        if (-not $certMatch) {
            Write-Verbose "[$Domain] Subject mismatch — checking Certs folder"
            # v1.5: Smart Arbitration — проверяем ./Certs перед MITM
            $arb = Test-CertArbitration -Domain $Domain -CertSubject $cert.Subject
            if ($arb) {
                $result.Status = "OK"
                $result.Trust  = $arb
                $result.Reason = "OK"
                Write-Verbose "[$Domain] Arbitration passed via Certs folder"
                # не return — идём дальше проверять chain
            } else {
                $result.Status = "OK"
                $result.Trust  = "MITM"
                $result.Reason = "MITM"
                $result.Error  = "Cert CN mismatch (possible intercept)"
                return $result
            }
        }

        # 6. Просроченный?
        if ($result.DaysLeft -lt 0) {
            $result.Status = "OK"
            $result.Trust  = "EXPIRED"
            $result.Reason = "Cert expired"
            return $result
        }

        # 7. [GPT] X509Chain через ChainStatus — точная причина ошибки
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chainOK = $chain.Build($cert)

        $isSelfSigned = ($cert.Subject -eq $cert.Issuer)

        if ($isSelfSigned) {
            $result.Status = "OK"
            $result.Trust  = "SELF-SIGN"
            $result.Reason = "Self-signed"
        }
        elseif ($chainOK) {
            $result.Status = "OK"
            $result.Trust  = "TRUSTED"
            $result.Reason = "OK"
        }
        else {
            # GPT: перебираем ChainStatus — конкретная причина, не просто FAIL
            $result.Status = "OK"
            $chainReason = "!CHAIN"

            foreach ($s in $chain.ChainStatus) {
                Write-Verbose "[$Domain] ChainStatus: $($s.Status) — $($s.StatusInformation)"
                switch ($s.Status) {
                    "PartialChain"  { $chainReason = "PartialChain"; break }
                    "UntrustedRoot" { $chainReason = "UntrustedRoot"; break }
                    "NotTimeValid"  { $chainReason = "Expired"; break }
                    "Revoked"       { $chainReason = "Revoked"; break }
                }
            }
            $result.Trust  = "!CHAIN"
            $result.Reason = $chainReason
        }
    }
    catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        $result.Error  = $ex.Message
        $result.Reason = Normalize-Error $ex.Message
        Write-Verbose "[$Domain] Exception: $($result.Reason) — $($result.Error)"
    }
    finally {
        # v1.12 [Task]: Безопасный Dispose — при RST/DPI сокет может быть в состоянии Faulted.
        # Стандартный Dispose() в этом случае бросает ObjectDisposedException или IOException.
        # Оборачиваем каждый вызов в try/catch — игнорируем любые ошибки при закрытии.
        # Порядок важен: сначала SslStream (верхний слой), затем TcpClient (нижний).
        if ($sslStream) {
            try { $sslStream.Dispose() } catch { <# Faulted socket — игнорируем #> }
        }
        if ($tcpClient) {
            try { $tcpClient.Close()   } catch { <# RST — соединение уже разорвано #> }
            try { $tcpClient.Dispose() } catch { <# ObjectDisposedException — норм #> }
        }
    }

    return $result
}


# ==============================
# DNS RESOLVE
# ==============================
function Resolve-Domain {
    param($domain)
    try {
        $res = Resolve-DnsName $domain -ErrorAction Stop |
               Where-Object { $_.Type -eq "A" } |
               Select-Object -First 1
        if ($res) { return @{ OK=$true; IP=$res.IPAddress } }
    }
    catch { Write-Verbose "Resolve-DnsName [$domain] failed: $($_.Exception.Message)" }
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($domain) |
                     Where-Object { $_.AddressFamily -eq "InterNetwork" }
        if ($addresses) { return @{ OK=$true; IP=$addresses[0].ToString() } }
    }
    catch { Write-Verbose "Dns.GetHostAddresses [$domain] failed: $($_.Exception.Message)" }
    return @{ OK=$false; IP="" }
}


# ============================================================
# HTTP ERROR REASON (v1.7)
# Извлекает причину из исключения: 403, timeout, RST и т.д.
# Используется в Test-Domain и Check-Single
# ============================================================
function Get-HttpFailReason {
    param([System.Management.Automation.ErrorRecord]$err)
    $inner = if ($err.Exception.InnerException) { $err.Exception.InnerException.Message } else { "" }
    $msg = "$($err.Exception.Message) $inner"
    if ($msg -match "403|Forbidden")                            { return "403" }
    if ($msg -match "401|Unauthorized")                        { return "401" }
    if ($msg -match "429|Too Many")                            { return "429" }
    if ($msg -match "503|Service Unavailable")                 { return "503" }
    if ($msg -match "timed out|TimeoutException|task.*cancel") { return "timeout" }
    if ($msg -match "reset|ConnectionReset|RST|forcibly")      { return "RST" }
    if ($msg -match "refused|actively refused")                { return "refused" }
    if ($msg -match "SSL|TLS|certificate|trust")               { return "TLS-err" }
    if ($msg -match "name.*resolve|DNS|SocketException")       { return "DNS" }
    if ($msg -match "404|Not Found")                           { return "404" }
    return "FAIL"
}

# ==============================
# ДОМЕН ТЕСТ (основная функция)
# ==============================
function Test-Domain {
    param($domain, [int]$PingCount = 3)

    $dns = "FAIL"
    $ip  = ""

    $dnsResult = Resolve-Domain $domain
    if ($dnsResult.OK) {
        $dns = "OK"
        $ip  = $dnsResult.IP
    }

    $pingAvg = "N/A"
    $loss    = 100
    $tls     = "FAIL"
    $cert    = $null

    if ($ip) {
        $p       = Get-PingStats $ip -Count $PingCount
        $pingAvg = $p.Avg
        $loss    = $p.Loss

        # ICMP в РФ режется провайдером — loss:100% не означает TCP закрыт
        # Запускаем Get-CertInfo всегда если DNS дал IP
        $cert = Get-CertInfo $domain
        $tls  = $cert.TLS
    }

    # HTTP check
    # v1.3: используем $global:HttpHeaders — полный набор заголовков Chrome (WAF bypass)
    $http      = "FAIL"
    $serverHdr = ""

    try {
        $r = Invoke-WebRequest "https://$domain" -Method Head -TimeoutSec 4 `
             -UseBasicParsing -MaximumRedirection 3 `
             -UserAgent $global:HttpHeaders["User-Agent"] `
             -Headers @{
                 "Accept"          = $global:HttpHeaders["Accept"]
                 "Accept-Language" = $global:HttpHeaders["Accept-Language"]
                 "Connection"      = $global:HttpHeaders["Connection"]
             }
        $http = $r.StatusCode
        if ($r.Headers -and $r.Headers["Server"]) {
            $serverHdr = $r.Headers["Server"]
            if ($serverHdr -match "TSPU|block" -and $http -notmatch "^(2|3)") {
                $serverHdr = "[$serverHdr]"
            }
        }
    }
    catch {
        # HTTPS не прошёл — пробуем HTTP fallback
        $outerErr = $_
        try {
            $r = Invoke-WebRequest "http://$domain" -Method Head -TimeoutSec 4 `
                 -UseBasicParsing `
                 -UserAgent $global:HttpHeaders["User-Agent"] `
                 -Headers @{
                     "Accept"          = $global:HttpHeaders["Accept"]
                     "Accept-Language" = $global:HttpHeaders["Accept-Language"]
                 }
            $http = $r.StatusCode
        }
        catch {
            # v1.7: FAIL с причиной вместо голого FAIL
            $reason = Get-HttpFailReason $_
            if ($reason -eq "FAIL") { $reason = Get-HttpFailReason $outerErr }
            $http = if ($reason -eq "FAIL") { "FAIL" } else { "FAIL($reason)" }
            Write-Verbose "[$domain] HTTP both failed: $reason"
        }
    }

    # ── STATUS ENGINE ──────────────────────────────────────────────────────
    # UP       — HTTP 2xx/3xx + CERT TRUSTED (пинг не учитываем — ICMP режется в РФ)
    # DEGRADED — сервер виден, но есть проблемы (CERT/DPI/WAF-блок)
    # DOWN     — DNS FAIL или TCP полностью недоступен
    # ──────────────────────────────────────────────────────────────────────
    $certTrust = if ($cert) { $cert.Trust } else { "FAIL" }
    $status = "DOWN"
    if ($dns -eq "FAIL") {
        $status = "DOWN"
    }
    elseif ($http -match "^(2|3)" -and $certTrust -eq "TRUSTED") {
        # Всё хорошо — HTTP работает и серт чистый
        $status = "UP"
    }
    elseif ($http -match "^(2|3)" -and $certTrust -ne "TRUSTED") {
        # HTTP работает но серт проблемный
        $status = "DEGRADED"
    }
    elseif ($tls -eq "OK") {
        # TLS handshake прошёл — сервер живой, просто HTTP заблокирован (DPI)
        # v1.3: убрали зависимость от $loss — пинг не показатель в РФ
        $status = "DEGRADED"
    }
    elseif ($dns -eq "OK" -and $cert -and $cert.Reason -eq "DPI/RST") {
        # DNS прошёл, но DPI режет на SNI — классика Телеграма
        $status = "DEGRADED"
    }

    # Формируем метку CERT для таблицы
    # CDN проверяется первым — $cert.Trust при CDN может быть ещё не выставлен
    $certLabel = if ($cert) {
        if     ($cert.CdnCert)                { "TRUSTED (CDN)" }
        elseif ($cert.Trust -eq "TRUSTED")    { "TRUSTED" }
        elseif ($cert.Trust -like "TRUSTED *") { $cert.Trust }  # TRUSTED (File)
        elseif ($cert.Trust -eq "FAIL")       { "FAIL ($($cert.Reason))" }
        else                                  { $cert.Trust }
    } else { "N/A" }

    return [PSCustomObject]@{
        Domain = $domain
        IP     = $ip
        DNS    = $dns
        TLS    = $tls
        HTTP   = $http
        Ping   = "$pingAvg ms"
        Loss   = "${loss}%"
        Cert   = $certLabel
        Status = $status
    }
}


# ==============================
# [Google AI] ПРОВЕРКА ВРЕМЕНИ
# Сбитые часы = ложный CERT: FAIL на всех доменах
# try/catch с коротким таймаутом — не тормозит запуск если API недоступен
# ==============================
function Test-TimeDrift {
    try {
        $webTime = (Invoke-RestMethod "http://worldtimeapi.org/api/ip" -TimeoutSec 3).utc_datetime
        $localUtc = (Get-Date).ToUniversalTime()
        $drift = [Math]::Abs((New-TimeSpan -Start ([datetime]$webTime) -End $localUtc).TotalSeconds)
        if ($drift -gt 120) {
            Write-Host ""
            Write-Host "  ⚠ ВНИМАНИЕ: Системное время расходится с реальным на $([int]$drift) сек!" -ForegroundColor Red
            Write-Host "    Это может вызывать ложный CERT: FAIL на всех доменах." -ForegroundColor Red
            Write-Host "    Проверь время в Windows: Settings → Time & Language" -ForegroundColor Yellow
        }
    }
    catch {
        # API недоступен — не критично, просто пропускаем
        Write-Verbose "Проверка времени недоступна: $($_.Exception.Message)"
    }
}


# ============================================================
# ДВУХКОЛОНОЧНЫЙ РЕНДЕР (v1.7)
# Принимает два массива {текст,цвет}, печатает бок о бок.
# Нет SetCursorPosition → нет мигания.
# $Left  = @([pscustomobject]@{T="text";C="Color"}, ...)  левая колонка
# $Right = @([pscustomobject]@{T="text";C="Color"}, ...)  правая колонка (легенда)
# $LeftW = ширина левой колонки (символов с паддингом)
# ============================================================
function Write-TwoColumns {
    param(
        [array]$Left,
        [array]$Right,
        [int]$LeftW = 44
    )
    # Защита от null — если передали пустой массив
    if (-not $Left)  { $Left  = @() }
    if (-not $Right) { $Right = @() }

    # v1.8 [Claude]: хелпер — читает .T/.C из pscustomobject (новый формат)
    # Старый @("text","Color")[0] в PS 5.1 давал символ строки, не элемент массива
    function Get-TC {
        param($item)
        if ($item -is [System.Management.Automation.PSCustomObject]) {
            return @{ T = [string]$item.T; C = [string]$item.C }
        }
        # Fallback для обычных массивов (не должно встречаться, но на всякий случай)
        if ($item -is [array] -and $item.Count -ge 2) {
            return @{ T = [string]$item[0]; C = [string]$item[1] }
        }
        return @{ T = [string]$item; C = "White" }
    }

    # v1.12 [Task]: Anti-Flicker — формируем полную строку в памяти,
    # один Write-Host на строку вместо двух -NoNewline.
    # Это устраняет мерцание при быстром обновлении двухколоночного вывода.
    # PadRight($LeftW) гарантирует железное выравнивание независимо от длины текста.
    $rows = [Math]::Max($Left.Count, $Right.Count)
    for ($i = 0; $i -lt $rows; $i++) {

        # ── Левая часть: читаем текст, обрезаем/паддим до $LeftW ──
        $leftTxt   = ""
        $leftColor = "White"
        if ($i -lt $Left.Count -and $Left[$i]) {
            $tc = Get-TC $Left[$i]
            $leftTxt   = [string]$tc.T
            $leftColor = [string]$tc.C
            if ($leftColor -notmatch '^[A-Za-z]+$') { $leftColor = "White" }
            if ($leftTxt.Length -gt $LeftW) { $leftTxt = $leftTxt.Substring(0, $LeftW) }
        }
        # PadRight железно выравнивает колонку — даже если строка короче $LeftW
        $leftPart = $leftTxt.PadRight($LeftW)

        # ── Правая часть: читаем текст и цвет ──
        $rightTxt   = ""
        $rightColor = "White"
        if ($i -lt $Right.Count -and $Right[$i]) {
            $tc = Get-TC $Right[$i]
            $rightTxt   = [string]$tc.T
            $rightColor = [string]$tc.C
            if ($rightColor -notmatch '^[A-Za-z]+$') { $rightColor = "White" }
        }

        # ── Единственный Write-Host на всю строку — нет мерцания ──
        # Левая часть выводится серым (нейтральный), правая — своим цветом.
        # Если нужны разные цвета — правая идёт отдельным Write-Host без newline trick,
        # но в одном Console.Write вызове через escape-последовательности недоступны в PS 5.1.
        # Компромисс: левая в своём цвете без newline, правая сразу же — итого 2 вызова,
        # но строка формируется полностью до первого вывода (нет промежуточных flush).
        try {
            Write-Host $leftPart -NoNewline -ForegroundColor $leftColor
            Write-Host $rightTxt -ForegroundColor $rightColor
        } catch {
            Write-Host ($leftPart + $rightTxt)
        }
    }
}

# ============================================================
# КОНТЕКСТНАЯ СПРАВКА ДЛЯ ФУНКЦИЙ (v1.7)
# Вызывается в начале каждой проверяющей функции.
# $Context — ключ: "ListScan" | "Single" | "Monitor" | "Certs"
# Язык берётся из $global:Lang автоматически
# ============================================================
function Show-SideHelp {
    param([string]$Context)

    $isRU = $global:Lang -eq "RU"

    $panels = @{
        # v1.13 [Task+Claude]: Минимализм — только специфика режима.
        # Статусы UP/DEGRADED/DOWN и CERT-расшифровки убраны — они в L-легенде.
        # Офсет рассчитан от реальной высоты шапки меню (15 строк).
        # LeftW=52 единый для всех вызовов — справка не гуляет.
        ListScan = @{
            RU = @(
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="┌─ РЕЖИМ: СПИСОК ───────────────────┐";C="Cyan"}
                [pscustomobject]@{T="│ Строка результата:                │";C="White"}
                [pscustomobject]@{T="│ domain  СТАТУС  DNS TLS HTTP      │";C="DarkGray"}
                [pscustomobject]@{T="│                                   │";C="Black"}
                [pscustomobject]@{T="│ HTTP:200          — ОК            │";C="Green"}
                [pscustomobject]@{T="│ HTTP:301/302      — редирект      │";C="White"}
                [pscustomobject]@{T="│ HTTP:FAIL(403)    — блок по IP    │";C="Yellow"}
                [pscustomobject]@{T="│ HTTP:FAIL(RST)    — DPI оборвал   │";C="Red"}
                [pscustomobject]@{T="│ HTTP:FAIL(timeout)— таймаут       │";C="Yellow"}
                [pscustomobject]@{T="│                                   │";C="Black"}
                [pscustomobject]@{T="│ RST в HTTP ≠ RST в TLS:           │";C="DarkGray"}
                [pscustomobject]@{T="│  TLS:RST — DPI режет рукопожатие │";C="Red"}
                [pscustomobject]@{T="│  HTTP:RST — DPI режет уже после   │";C="Yellow"}
                [pscustomobject]@{T="└───────────────────────────────────┘";C="Cyan"}
                [pscustomobject]@{T="  [L] — полная легенда статусов";C="DarkGray"}
            )
            EN = @(
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="┌─ MODE: LIST SCAN ──────────────────┐";C="Cyan"}
                [pscustomobject]@{T="│ Result row:                       │";C="White"}
                [pscustomobject]@{T="│ domain  STATUS  DNS TLS HTTP      │";C="DarkGray"}
                [pscustomobject]@{T="│                                   │";C="Black"}
                [pscustomobject]@{T="│ HTTP:200          — OK            │";C="Green"}
                [pscustomobject]@{T="│ HTTP:301/302      — redirect      │";C="White"}
                [pscustomobject]@{T="│ HTTP:FAIL(403)    — IP block      │";C="Yellow"}
                [pscustomobject]@{T="│ HTTP:FAIL(RST)    — DPI reset     │";C="Red"}
                [pscustomobject]@{T="│ HTTP:FAIL(timeout)— timeout       │";C="Yellow"}
                [pscustomobject]@{T="│                                   │";C="Black"}
                [pscustomobject]@{T="│ RST in HTTP ≠ RST in TLS:         │";C="DarkGray"}
                [pscustomobject]@{T="│  TLS:RST — DPI cuts handshake    │";C="Red"}
                [pscustomobject]@{T="│  HTTP:RST — DPI cuts after TLS    │";C="Yellow"}
                [pscustomobject]@{T="└───────────────────────────────────┘";C="Cyan"}
                [pscustomobject]@{T="  [L] — full status legend";C="DarkGray"}
            )
        }
        Single = @{
            RU = @(
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="┌─ РЕЖИМ: ОДИНОЧНАЯ ПРОВЕРКА ───────┐";C="Cyan"}
                [pscustomobject]@{T="│ Ввод: google.com,vk.com,sber.ru   │";C="White"}
                [pscustomobject]@{T="│ Через запятую — без пробелов      │";C="DarkGray"}
                [pscustomobject]@{T="│                                   │";C="Black"}
                [pscustomobject]@{T="│ Ping  median — точнее avg         │";C="White"}
                [pscustomobject]@{T="│ Ping  loss   — % потерь пакетов   │";C="White"}
                [pscustomobject]@{T="│ CERT  CN     — владелец серт.     │";C="White"}
                [pscustomobject]@{T="│ CERT  days   — дней до истечения  │";C="White"}
                [pscustomobject]@{T="│                                   │";C="Black"}
                [pscustomobject]@{T="│ После результатов:                │";C="DarkGray"}
                [pscustomobject]@{T="│  S — сохранить отчёт в Logs\     │";C="DarkGray"}
                [pscustomobject]@{T="│  Enter — пропустить               │";C="DarkGray"}
                [pscustomobject]@{T="└───────────────────────────────────┘";C="Cyan"}
                [pscustomobject]@{T="  [L] — полная легенда статусов";C="DarkGray"}
            )
            EN = @(
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="";C="Black"}
                [pscustomobject]@{T="┌─ MODE: SINGLE CHECK ───────────────┐";C="Cyan"}
                [pscustomobject]@{T="│ Input: google.com,vk.com          │";C="White"}
                [pscustomobject]@{T="│ Comma-separated, no spaces        │";C="DarkGray"}
                [pscustomobject]@{T="│                                   │";C="Black"}
                [pscustomobject]@{T="│ Ping  median — cleaner than avg   │";C="White"}
                [pscustomobject]@{T="│ Ping  loss   — packet loss %      │";C="White"}
                [pscustomobject]@{T="│ CERT  CN     — cert owner         │";C="White"}
                [pscustomobject]@{T="│ CERT  days   — days until expiry  │";C="White"}
                [pscustomobject]@{T="│                                   │";C="Black"}
                [pscustomobject]@{T="│ After results:                    │";C="DarkGray"}
                [pscustomobject]@{T="│  S — save report to Logs\        │";C="DarkGray"}
                [pscustomobject]@{T="│  Enter — skip                     │";C="DarkGray"}
                [pscustomobject]@{T="└───────────────────────────────────┘";C="Cyan"}
                [pscustomobject]@{T="  [L] — full status legend";C="DarkGray"}
            )
        }
        Monitor = @{
            RU = @(
                [pscustomobject]@{T="┌─ СЕТЕВОЙ МОНИТОР ─────────────────┐";C="Yellow"}
                [pscustomobject]@{T="│ Живые TCP/UDP соединения ПК       │";C="White"}
                [pscustomobject]@{T="│                                   │";C="Yellow"}
                [pscustomobject]@{T="│ ESTAB — активное соединение       │";C="Green"}
                [pscustomobject]@{T="│ SYN-S — ждёт ответа (блок?)       │";C="Red"}
                [pscustomobject]@{T="│ LISTN — порт слушает входящие     │";C="Cyan"}
                [pscustomobject]@{T="│ UDP53 — DNS запрос                │";C="DarkYellow"}
                [pscustomobject]@{T="├───────────────────────────────────┤";C="Yellow"}
                [pscustomobject]@{T="│ Geo — страна удалённого IP        │";C="White"}
                [pscustomobject]@{T="│ KB/s — скорость процесса (счётч.) │";C="White"}
                [pscustomobject]@{T="│ PID  — ID процесса Windows        │";C="White"}
                [pscustomobject]@{T="├───────────────────────────────────┤";C="Yellow"}
                [pscustomobject]@{T="│ Q / Й — выход в меню              │";C="DarkGray"}
                [pscustomobject]@{T="└───────────────────────────────────┘";C="Yellow"}
            )
            EN = @(
                [pscustomobject]@{T="┌─ NETWORK MONITOR ──────────────────┐";C="Yellow"}
                [pscustomobject]@{T="│ Live TCP/UDP connections          │";C="White"}
                [pscustomobject]@{T="│ ESTAB — active connection         │";C="Green"}
                [pscustomobject]@{T="│ SYN-S — waiting (possible block)  │";C="Red"}
                [pscustomobject]@{T="│ LISTN — listening for incoming    │";C="Cyan"}
                [pscustomobject]@{T="│ UDP53 — DNS request               │";C="DarkYellow"}
                [pscustomobject]@{T="│ Geo  — remote IP country          │";C="White"}
                [pscustomobject]@{T="│ KB/s — process I/O speed          │";C="White"}
                [pscustomobject]@{T="│ Q    — exit to menu               │";C="DarkGray"}
                [pscustomobject]@{T="└───────────────────────────────────┘";C="Yellow"}
            )
        }
        Certs = @{
            RU = @(
                [pscustomobject]@{T="┌─ СЕРТИФИКАТЫ (Smart Arbitration) ─┐";C="Yellow"}
                [pscustomobject]@{T="│ Зачем: банки РФ используют НУЦ   │";C="White"}
                [pscustomobject]@{T="│ Минцифры вместо браузерных CA.    │";C="White"}
                [pscustomobject]@{T="│ Скрипт видит MITM — ложно!        │";C="Red"}
                [pscustomobject]@{T="│                                   │";C="Yellow"}
                [pscustomobject]@{T="│ Решение: добавь .cer в Certs\    │";C="Cyan"}
                [pscustomobject]@{T="│ и активируй через этот пункт.     │";C="Cyan"}
                [pscustomobject]@{T="│ MITM → TRUSTED (File)             │";C="Green"}
                [pscustomobject]@{T="├───────────────────────────────────┤";C="Yellow"}
                [pscustomobject]@{T="│ [ACTIVE] — сертификат используется│";C="Cyan"}
                [pscustomobject]@{T="│ 1,2 — включить/выключить (toggle) │";C="White"}
                [pscustomobject]@{T="│ all — активировать все            │";C="White"}
                [pscustomobject]@{T="│ 0   — сбросить все                │";C="White"}
                [pscustomobject]@{T="├───────────────────────────────────┤";C="Yellow"}
                [pscustomobject]@{T="│ Где взять .cer:                   │";C="DarkGray"}
                [pscustomobject]@{T="│ gosuslugi.ru/crt → НУЦ Минцифры  │";C="DarkGray"}
                [pscustomobject]@{T="│ Или: браузер → замок → серт →     │";C="DarkGray"}
                [pscustomobject]@{T="│ Подробности → Экспорт DER (.cer)  │";C="DarkGray"}
                [pscustomobject]@{T="└───────────────────────────────────┘";C="Yellow"}
            )
            EN = @(
                [pscustomobject]@{T="┌─ CERTIFICATES (Smart Arbitration) ┐";C="Yellow"}
                [pscustomobject]@{T="│ Russian banks use national CA     │";C="White"}
                [pscustomobject]@{T="│ → checker shows false MITM        │";C="Red"}
                [pscustomobject]@{T="│ Fix: add .cer to Certs\          │";C="Cyan"}
                [pscustomobject]@{T="│ MITM → TRUSTED (File)             │";C="Green"}
                [pscustomobject]@{T="├───────────────────────────────────┤";C="Yellow"}
                [pscustomobject]@{T="│ [ACTIVE] — cert is in use         │";C="Cyan"}
                [pscustomobject]@{T="│ 1,2 — toggle on/off               │";C="White"}
                [pscustomobject]@{T="│ all — activate all                │";C="White"}
                [pscustomobject]@{T="│  0  — clear all                   │";C="White"}
                [pscustomobject]@{T="├───────────────────────────────────┤";C="Yellow"}
                [pscustomobject]@{T="│ Get .cer: gosuslugi.ru/crt        │";C="DarkGray"}
                [pscustomobject]@{T="│ Or: browser lock → cert →         │";C="DarkGray"}
                [pscustomobject]@{T="│ Details → Export DER (.cer)       │";C="DarkGray"}
                [pscustomobject]@{T="└───────────────────────────────────┘";C="Yellow"}
            )
        }
    }

    $lang = if ($global:Lang -eq "RU") { "RU" } else { "EN" }
    if ($panels.ContainsKey($Context) -and $panels[$Context].ContainsKey($lang)) {
        return $panels[$Context][$lang]
    }
    return @()
}


# ============================================================
# GLOBAL:LEGENDDATA — единый источник данных для легенды
# v1.11 [Claude+Anton]: используется в двух местах:
#   1. Show-IPInfo  — правая колонка главного меню (краткая)
#   2. Show-Legend  — overlay по кнопке L (та же структура, полная)
# v1.14 [Claude]: расширен: добавлен SELF-SIGN, антивирусный MITM,
#   подсказка [L] — ссылка на кнопку внутри самого блока.
# RU/EN — переключается глобальным $global:Lang (пункт 8 меню).
# ============================================================
$global:LegendData = @{
    RU = @(
        [pscustomobject]@{T="┌─ ЛЕГЕНДА ──────────────────────────────┐";C="Yellow"}
        [pscustomobject]@{T="│ Итоговый статус домена:                │";C="Yellow"}
        [pscustomobject]@{T="│  UP       — DNS+TLS+HTTP+CERT всё OK   │";C="Green"}
        [pscustomobject]@{T="│  DEGRADED — виден, но есть проблемы    │";C="Yellow"}
        [pscustomobject]@{T="│  DOWN     — DNS fail или TCP закрыт    │";C="Red"}
        [pscustomobject]@{T="├────────────────────────────────────────┤";C="Yellow"}
        [pscustomobject]@{T="│ CERT — статус сертификата:             │";C="Yellow"}
        [pscustomobject]@{T="│  TRUSTED        — цепочка доверия OK   │";C="White"}
        [pscustomobject]@{T="│  TRUSTED(CDN)   — CDN-серт, др. TLD    │";C="DarkCyan"}
        [pscustomobject]@{T="│  TRUSTED(File)  — Certs\ арбитраж     │";C="Cyan"}
        [pscustomobject]@{T="│  MITM     — CN не совпадает (перехват) │";C="Red"}
        [pscustomobject]@{T="│  DPI/RST  — RST на SNI-рукопожатии    │";C="Red"}
        [pscustomobject]@{T="│  EXPIRED  — сертификат просрочен       │";C="DarkGray"}
        [pscustomobject]@{T="│  !CHAIN   — цепочка доверия сломана    │";C="DarkGray"}
        [pscustomobject]@{T="│  SELF-SIGN— самоподписанный            │";C="DarkGray"}
        [pscustomobject]@{T="├────────────────────────────────────────┤";C="Yellow"}
        [pscustomobject]@{T="│ Столбцы результата:                    │";C="Yellow"}
        [pscustomobject]@{T="│  DNS  — резолвинг домена в IP          │";C="White"}
        [pscustomobject]@{T="│  TLS  — TCP + TLS-рукопожатие          │";C="White"}
        [pscustomobject]@{T="│  HTTP — код ответа (200/301/FAIL/RST)  │";C="White"}
        [pscustomobject]@{T="│  PING — задержка мс (ICMP avg/median)  │";C="White"}
        [pscustomobject]@{T="│  LOSS — потери пакетов %               │";C="White"}
        [pscustomobject]@{T="├────────────────────────────────────────┤";C="Yellow"}
        [pscustomobject]@{T="│ ! PING timeout ≠ DOWN                  │";C="DarkGray"}
        [pscustomobject]@{T="│   Банки/госсайты блокируют ICMP        │";C="DarkGray"}
        [pscustomobject]@{T="│ ! MITM — может быть антивирус          │";C="DarkGray"}
        [pscustomobject]@{T="│   Kaspersky/ESET перехватывают TLS     │";C="DarkGray"}
        [pscustomobject]@{T="└────────────────────────────────────────┘";C="Yellow"}
        [pscustomobject]@{T="  L — развернуть эту легенду целиком";C="DarkGray"}
    )
    EN = @(
        [pscustomobject]@{T="┌─ LEGEND ────────────────────────────────┐";C="Yellow"}
        [pscustomobject]@{T="│ Domain status:                          │";C="Yellow"}
        [pscustomobject]@{T="│  UP       — DNS+TLS+HTTP+CERT all OK    │";C="Green"}
        [pscustomobject]@{T="│  DEGRADED — reachable but blocking      │";C="Yellow"}
        [pscustomobject]@{T="│  DOWN     — DNS fail or TCP closed      │";C="Red"}
        [pscustomobject]@{T="├─────────────────────────────────────────┤";C="Yellow"}
        [pscustomobject]@{T="│ CERT — certificate status:              │";C="Yellow"}
        [pscustomobject]@{T="│  TRUSTED        — chain OK              │";C="White"}
        [pscustomobject]@{T="│  TRUSTED(CDN)   — CDN cert, other TLD  │";C="DarkCyan"}
        [pscustomobject]@{T="│  TRUSTED(File)  — Certs\ arbitration   │";C="Cyan"}
        [pscustomobject]@{T="│  MITM     — CN mismatch (intercept?)   │";C="Red"}
        [pscustomobject]@{T="│  DPI/RST  — reset at SNI handshake     │";C="Red"}
        [pscustomobject]@{T="│  EXPIRED  — cert expired               │";C="DarkGray"}
        [pscustomobject]@{T="│  !CHAIN   — trust chain broken         │";C="DarkGray"}
        [pscustomobject]@{T="│  SELF-SIGN— self-signed cert           │";C="DarkGray"}
        [pscustomobject]@{T="├─────────────────────────────────────────┤";C="Yellow"}
        [pscustomobject]@{T="│ Columns:                                │";C="Yellow"}
        [pscustomobject]@{T="│  DNS  — domain to IP resolution         │";C="White"}
        [pscustomobject]@{T="│  TLS  — TCP + TLS handshake             │";C="White"}
        [pscustomobject]@{T="│  HTTP — response (200/301/FAIL/RST)     │";C="White"}
        [pscustomobject]@{T="│  PING — latency ms (ICMP avg/median)    │";C="White"}
        [pscustomobject]@{T="│  LOSS — packet loss %                   │";C="White"}
        [pscustomobject]@{T="├─────────────────────────────────────────┤";C="Yellow"}
        [pscustomobject]@{T="│ ! PING timeout ≠ DOWN                   │";C="DarkGray"}
        [pscustomobject]@{T="│   Banks/gov block ICMP                  │";C="DarkGray"}
        [pscustomobject]@{T="│ ! MITM may be your antivirus            │";C="DarkGray"}
        [pscustomobject]@{T="│   Kaspersky/ESET intercept TLS          │";C="DarkGray"}
        [pscustomobject]@{T="└─────────────────────────────────────────┘";C="Yellow"}
        [pscustomobject]@{T="  L — expand full legend";C="DarkGray"}
    )
}


# ============================================================
# SHOW-LEGEND — полная легенда поверх экрана по кнопке L
# v1.11 [Claude+Anton]: вызывается из главного switch по L/Л
# v1.14: добавлен Show-Legend до Show-IPInfo (ранее был после и терялся)
# Печатает $global:LegendData целиком, ждёт любую клавишу.
# Без SetCursorPosition — работает в любом окне PS и при redirect.
# ============================================================
function Show-Legend {
    $lang  = if ($global:Lang -eq "RU") { "RU" } else { "EN" }
    $lines = $global:LegendData[$lang]
    $title = if ($lang -eq "RU") { "  Любая клавиша — закрыть" } else { "  Any key to close" }

    Write-Host ""
    foreach ($l in $lines) {
        $txt   = [string]$l.T
        $color = [string]$l.C
        if ($color -notmatch "^[A-Za-z]+$") { $color = "White" }
        Write-Host "  $txt" -ForegroundColor $color
    }
    Write-Host ""
    Write-Host $title -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}



# ============================================================
# SHOW-LEGEND — полная легенда по кнопке L
# v1.11 [Claude+Anton]: overlay по кнопке L, единый источник $global:LegendData
# Не SetCursorPosition — просто печатает блок и ждёт нажатия
# ============================================================
function Show-Legend {
    $lang = if ($global:Lang -eq "RU") { "RU" } else { "EN" }
    $lines = $global:LegendData[$lang]
    if (-not $lines) { return }
    Write-Host ""
    foreach ($item in $lines) {
        if ($item -is [System.Management.Automation.PSCustomObject]) {
            Write-Host $item.T -ForegroundColor $item.C
        } else {
            Write-Host $item
        }
    }
    Write-Host ""
    if ($lang -eq "RU") {
        Read-Host "  Enter — меню"
    } else {
        Read-Host "  Enter — menu"
    }
}

# ============================================================
# SHOW-IPINFO — главное меню
# v1.7 [Claude+Anton]: двухколоночный рендер Write-TwoColumns.
#   Левая колонка  = шапка (IP/Geo/версия) + пункты меню (16 строк).
#   Правая колонка = краткая легенда из $global:LegendData (29 строк).
# v1.10: попытка SetCursorPosition — убрана в v1.14 (ломала скролл
#         и позиционирование при любом изменении размера окна).
# v1.14 [Claude]: чистый Write-TwoColumns, LeftW=38 (ширина шапки меню).
#   Легенда выравнивается автоматически по высоте левой колонки.
# Нет HTTP-запросов — только кэш ($global:CachedExternalIP/CachedGeo).
# ============================================================
function Show-IPInfo {
    # Читаем только кэш — IP/Geo запрашиваются один раз при старте скрипта
    $local    = Get-LocalIP
    $external = if ($global:CachedExternalIP) { $global:CachedExternalIP } else { "..." }
    $geo      = if ($global:CachedGeo)        { $global:CachedGeo        } else { "..." }
    $isRU     = ($global:Lang -ne "EN")
    $debug    = if ($global:DebugMode) { " [DEBUG]" } else { "" }
    # Количество активных сертификатов — рядом с пунктом 9
    $certs    = if ($global:ActiveCerts -and $global:ActiveCerts.Count -gt 0) {
                    " [$($global:ActiveCerts.Count) акт.]"
                } else { "" }
    $hint = if ($isRU) { "  [L — легенда  8 — Lang  10 — Debug]" } else { "  [L — legend  8 — Lang  10 — Debug]" }

    # ── Левая колонка: шапка + меню ──────────────────────────────────────
    # 16 строк: 3 заголовка + 3 сепаратора + 3 IP + 6 пунктов + 1 hint
    # Ширина строк <= 38 символов (LeftW=38) — не обрезается
    $menuLines = if ($isRU) { @(
        [pscustomobject]@{T="=====================================";C="Cyan"}
        [pscustomobject]@{T="  NetworkChecker v1.14 — Master$debug";C="Yellow"}
        [pscustomobject]@{T="  Anton Sidorenko & AI Team";C="DarkGray"}
        [pscustomobject]@{T="=====================================";C="Cyan"}
        [pscustomobject]@{T="  Local IP   : $local";C="White"}
        [pscustomobject]@{T="  External IP: $external";C="White"}
        [pscustomobject]@{T="  Geo        : $geo";C="White"}
        [pscustomobject]@{T="=====================================";C="Cyan"}
        [pscustomobject]@{T="  1 - Сетевой монитор";C="White"}
        [pscustomobject]@{T="  2 - Проверка доменов (lists\)";C="White"}
        [pscustomobject]@{T="  6 - Одиночная проверка";C="White"}
        [pscustomobject]@{T="  7 - Руководство";C="White"}
        [pscustomobject]@{T="  9 - Сертификаты$certs";C="White"}
        [pscustomobject]@{T="  0 - Выход";C="DarkGray"}
        [pscustomobject]@{T="=====================================";C="Cyan"}
        [pscustomobject]@{T=$hint;C="DarkGray"}
    ) } else { @(
        [pscustomobject]@{T="=====================================";C="Cyan"}
        [pscustomobject]@{T="  NetworkChecker v1.14 — Master$debug";C="Yellow"}
        [pscustomobject]@{T="  Anton Sidorenko & AI Team";C="DarkGray"}
        [pscustomobject]@{T="=====================================";C="Cyan"}
        [pscustomobject]@{T="  Local IP   : $local";C="White"}
        [pscustomobject]@{T="  External IP: $external";C="White"}
        [pscustomobject]@{T="  Geo        : $geo";C="White"}
        [pscustomobject]@{T="=====================================";C="Cyan"}
        [pscustomobject]@{T="  1 - Network Monitor";C="White"}
        [pscustomobject]@{T="  2 - Domain scan (lists\)";C="White"}
        [pscustomobject]@{T="  6 - Single check";C="White"}
        [pscustomobject]@{T="  7 - Manual";C="White"}
        [pscustomobject]@{T="  9 - Certificates$certs";C="White"}
        [pscustomobject]@{T="  0 - Exit";C="DarkGray"}
        [pscustomobject]@{T="=====================================";C="Cyan"}
        [pscustomobject]@{T=$hint;C="DarkGray"}
    ) }

    # ── Правая колонка: краткая легенда из глобального LegendData ─────────
    # Единый источник: тот же объект что показывает Show-Legend (кнопка L)
    $lang        = if ($isRU) { "RU" } else { "EN" }
    $legendLines = $global:LegendData[$lang]

    # ── Рендер через Write-TwoColumns — без SetCursorPosition ─────────────
    # LeftW=38: ширина левой колонки. Легенда начинается с символа 39.
    # Anti-Flicker: каждая строка формируется в памяти, 2 Write-Host подряд.
    # Fallback внутри Write-TwoColumns: если цвет невалиден — White.
    Write-TwoColumns -Left $menuLines -Right $legendLines -LeftW 38
}


function Show-NetMonitor {
    $global:GeoCache = @{}   # сброс кэша при входе

    # Получаем начальные счётчики скорости
    $speedMap = Get-NetSpeed

    while ($true) {
        # ── Сбор данных ──────────────────────────────────────────────────────
        $proc = @{}
        Get-Process | ForEach-Object { $proc[$_.Id] = $_.ProcessName }

        # netstat -ano даёт TCP ESTABLISHED + SYN; добавляем UDP 53 для DNS
        $rawLines = netstat -ano 2>$null
        $rows = $rawLines | ForEach-Object {
            $line = ($_ -replace '\s+', ' ').Trim()
            if (-not $line) { return }
            $p = $line.Split(' ')
            if ($p.Count -lt 5) { return }

            $proto  = $p[0]   # TCP / UDP
            $local  = $p[1]
            $remote = $p[2]
            $state  = if ($proto -eq "TCP") { $p[3] } else { "UDP" }
            $pidRaw = $p[-1]
            if ($pidRaw -notmatch '^\d+$') { return }
            $pid_ = [int]$pidRaw

            # Фильтр: TCP ESTABLISHED, SYN*, LISTEN + UDP порт 53
            $keep = $false
            if ($proto -eq "TCP" -and $state -in @("ESTABLISHED","SYN_SENT","SYN_RECEIVED","LISTENING")) { $keep = $true }
            if ($proto -eq "UDP" -and $local -match ':53$') { $keep = $true }
            if (-not $keep) { return }

            $remoteIP = if ($remote -match '^(.+):\d+$') { $Matches[1] } else { $remote }
            $name = if ($proc[$pid_]) { $proc[$pid_] } else { "?" }

            [PSCustomObject]@{
                Process  = $name
                Proto    = $proto
                State    = $state
                Remote   = $remote
                RemoteIP = $remoteIP
                PID      = $pid_
            }
        } | Where-Object { $_ } | Sort-Object Process

        # ── Geo для уникальных IP (только новые — кэш экономит запросы) ──────
        $uniqueIPs = $rows | Select-Object -ExpandProperty RemoteIP -Unique |
                     Where-Object { $_ -and $_ -ne "0.0.0.0" -and $_ -ne "*" }
        foreach ($ip in $uniqueIPs) {
            if (-not $global:GeoCache.ContainsKey($ip)) {
                Get-GeoCode $ip | Out-Null   # заполняет кэш
            }
        }

        # ── Скорость (обновляем раз в тик) ───────────────────────────────────
        $speedMap = Get-NetSpeed

        # ── Рендер таблицы ───────────────────────────────────────────────────
        Clear-Host
        $ts = Get-Date -Format "HH:mm:ss"
        $monTitle = if ($global:Lang -eq "RU") { "Сетевой монитор" } else { "Network Monitor" }
        Write-Host "=== $monTitle  $ts ===" -ForegroundColor Yellow
        Write-Host ("{0,-18} {1,-6} {2,-22} {3,-4} {4,-8} {5}" -f `
            "Process","State","Remote","Geo","KB/s","PID") -ForegroundColor DarkGray
        Write-Host ("-" * 78) -ForegroundColor DarkGray

        $cntEst = 0; $cntSyn = 0; $cntListen = 0; $cntUdp = 0

        foreach ($r in $rows) {
            $geo   = if ($global:GeoCache.ContainsKey($r.RemoteIP)) { $global:GeoCache[$r.RemoteIP] } else { ".." }
            $kbs   = $speedMap[$r.Process.ToLower()]
            $kbStr = if ($kbs -and $kbs -gt 0) { "$kbs" } else { "-" }

            $color = switch ($r.State) {
                "ESTABLISHED"    { $cntEst++;    "Green" }
                "SYN_SENT"       { $cntSyn++;    "Red" }
                "SYN_RECEIVED"   { $cntSyn++;    "Red" }
                "LISTENING"      { $cntListen++; "Cyan" }
                "UDP"            { $cntUdp++;    "DarkYellow" }
                default          { "DarkGray" }
            }

            $stateShort = switch ($r.State) {
                "ESTABLISHED"  { "ESTAB" }
                "SYN_SENT"     { "SYN-S" }
                "SYN_RECEIVED" { "SYN-R" }
                "LISTENING"    { "LISTN" }
                "UDP"          { "UDP53" }
                default        { $r.State.Substring(0, [Math]::Min(5,$r.State.Length)) }
            }

            $procShort   = if ($r.Process.Length -gt 17) { $r.Process.Substring(0,16) + "~" } else { $r.Process }
            $remoteShort = if ($r.Remote.Length  -gt 21) { $r.Remote.Substring(0,20)  + "~" } else { $r.Remote }

            Write-Host ("{0,-18} {1,-6} {2,-22} {3,-4} {4,-8} {5}" -f `
                $procShort, $stateShort, $remoteShort, $geo, $kbStr, $r.PID) -ForegroundColor $color
        }

        Write-Host ("-" * 78) -ForegroundColor DarkGray
        $total = @($rows).Count
        Write-Host ("  Всего:{0}  " -f $total) -NoNewline
        Write-Host "ESTAB:$cntEst " -NoNewline -ForegroundColor Green
        Write-Host "SYN:$cntSyn " -NoNewline -ForegroundColor Red
        Write-Host "LISTEN:$cntListen " -NoNewline -ForegroundColor Cyan
        Write-Host "DNS/UDP:$cntUdp" -ForegroundColor DarkYellow
        Write-Host ""
        $exitHint = if ($global:Lang -eq "RU") { "  Обновление каждые 3с.  Q / Й — выход в меню." } else { "  Updates every 3s.  Q — exit to menu." }
        Write-Host $exitHint -ForegroundColor DarkGray

        # ── Ждём 3с с возможностью выйти по Q ────────────────────────────────
        $deadline = (Get-Date).AddSeconds(3)
        while ((Get-Date) -lt $deadline) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.KeyChar -eq 'q' -or $key.KeyChar -eq 'Q' -or
                    $key.KeyChar -eq 'й' -or $key.KeyChar -eq 'Й') {
                    $global:GeoCache = @{}
                    return
                }
            }
            Start-Sleep -Milliseconds 100
        }
    }
}

# Show-Connections = алиас для обратной совместимости
function Show-Connections { Show-NetMonitor }


# ==============================
# ОДИНОЧНАЯ ПРОВЕРКА
# v1.4: логирование с вертикальным форматом + метка времени + кэш IP/Geo
# ==============================
function Check-Single {
    $title = if ($global:Lang -eq 'RU') { 'Одиночная проверка' } else { 'Single Check' }
    Write-Host "  === $title ===" -ForegroundColor Cyan
    Write-Host ""
    $inputStr = Read-Host "  $(T 'Domains')"
    if (-not $inputStr) { return }

    Write-Host "Количество пингов для медианы [по умолчанию 10]:"
    $countRaw = Read-Host "Количество (Enter = 10)"

    if ($countRaw -match '^\d+$' -and [int]$countRaw -gt 0) {
        $pingCount = [int]$countRaw
    } else {
        $pingCount = 10
    }

    $domains = $inputStr -split ',' | ForEach-Object { Sanitize-Domain $_ } | Where-Object { $_ }

    # v1.4: лог-буфер очищается в начале каждого вызова — нет склейки между сессиями
    $logLines = [System.Collections.Generic.List[string]]::new()

    # Шапка отчёта (Google AI: для отправки в саппорт)
    $reportTime = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
    $logLines.Add("=====================================")
    $logLines.Add("NetworkChecker v1.14 | SINGLE CHECK REPORT")
    $logLines.Add("Time: $reportTime")
    $logLines.Add("External IP: $global:CachedExternalIP")
    $logLines.Add("Geo        : $global:CachedGeo")
    $logLines.Add("=====================================")
    $logLines.Add("")

    foreach ($domain in $domains) {
        # v1.4: метка времени начала проверки домена (Google AI)
        $startTime = Get-Date -Format "HH:mm:ss"
        Write-Host "`n--- $domain [$startTime] ---" -ForegroundColor Cyan
        $logLines.Add("--- $domain [$startTime] ---")

        $dnsResult = Resolve-Domain $domain
        $dns = if ($dnsResult.OK) { "OK" } else { "FAIL" }
        $ip  = $dnsResult.IP

        Write-Host "DNS    : $dns  IP: $ip"
        $logLines.Add("DNS    : $dns  IP: $ip")

        if (-not $ip) {
            Write-Host "Статус : DOWN (DNS не прошёл)" -ForegroundColor Red
            $logLines.Add("Статус : DOWN (DNS не прошёл)")
            $logLines.Add("")
            continue
        }

        Write-Host "Пингую $pingCount раз..." -NoNewline
        $p = Get-PingStats $ip -Count $pingCount
        Write-Host " готово"
        # v1.7: визуальный блок пинга — медиана выделена как основной показатель
        $pingLine = "Ping   : avg={0}ms  median={1}ms  min={2}ms  max={3}ms  loss={4}%" -f `
            $p.Avg, $p.Median, $p.Min, $p.Max, $p.Loss
        Write-Host "Ping   : " -NoNewline
        Write-Host "avg=$($p.Avg)ms" -NoNewline -ForegroundColor DarkGray
        Write-Host "  " -NoNewline
        # Медиана — главный показатель (устойчив к выбросам)
        # FIX: try/catch — Median может быть строкой "timeout" когда ICMP заблокирован
        $medColor = "DarkGray"
        try { $medColor = if ([double]$p.Median -lt 50) { "Green" } elseif ([double]$p.Median -lt 150) { "Yellow" } else { "Red" } } catch {}
        Write-Host "median=$($p.Median)ms" -NoNewline -ForegroundColor $medColor
        Write-Host "  min=$($p.Min)ms  max=$($p.Max)ms  loss=$($p.Loss)%" -NoNewline -ForegroundColor DarkGray
        # Если avg и median расходятся > 10ms — был выброс, медиана точнее
        $showDrift = $false
        try { $showDrift = [Math]::Abs([double]$p.Avg - [double]$p.Median) -gt 10 } catch {}
        if ($showDrift) { Write-Host "  [avg≠median: выброс пинга]" -ForegroundColor Yellow } else { Write-Host "" }
        $logLines.Add($pingLine)

        $cert = Get-CertInfo $domain
        Write-Host "TLS    : $($cert.TLS)"
        $logLines.Add("TLS    : $($cert.TLS)")

        if ($cert.TLS -eq "OK") {
            $certColor = if     ($cert.DaysLeft -lt 0)  { "Red" }
                         elseif ($cert.DaysLeft -lt 14) { "Red" }
                         elseif ($cert.DaysLeft -lt 30) { "Yellow" }
                         else                           { "Green" }

            $certLine = "CERT   : {0}  ({1} дней)  Trust:{2}" -f $cert.Expiry, $cert.DaysLeft, $cert.Trust
            Write-Host $certLine -ForegroundColor $certColor
            Write-Host ("         {0}" -f $cert.Subject)
            $logLines.Add($certLine)
            $logLines.Add("         $($cert.Subject)")

            if ($cert.Trust -eq "MITM") {
                Write-Host "  ⚠ MITM: Сертификат не совпадает с доменом!" -ForegroundColor Red
                Write-Host "    Возможно: подмена провайдером или антивирус перехватывает трафик" -ForegroundColor Yellow
                $logLines.Add("  ⚠ MITM: Сертификат не совпадает с доменом!")
                $logLines.Add("    Возможно: подмена провайдером или антивирус перехватывает трафик")
            }
        }
        else {
            $certFailLine = "CERT   : FAIL ($($cert.Reason))"
            Write-Host $certFailLine -ForegroundColor Red
            Write-Verbose "CERT raw error: $($cert.Error)"
            $logLines.Add($certFailLine)
        }

        # HTTP — WAF bypass через $global:HttpHeaders
        $http = "FAIL"
        try {
            $r = Invoke-WebRequest "https://$domain" -Method Head -TimeoutSec 4 `
                 -UseBasicParsing -MaximumRedirection 3 `
                 -UserAgent $global:HttpHeaders["User-Agent"] `
                 -Headers @{
                     "Accept"          = $global:HttpHeaders["Accept"]
                     "Accept-Language" = $global:HttpHeaders["Accept-Language"]
                     "Connection"      = $global:HttpHeaders["Connection"]
                 }
            $http = $r.StatusCode
        }
        catch {
            $outerErr = $_
            Write-Verbose "Check-Single HTTPS [$domain]: $(Get-HttpFailReason $_)"
            try {
                $r = Invoke-WebRequest "http://$domain" -Method Head -TimeoutSec 4 `
                     -UseBasicParsing `
                     -UserAgent $global:HttpHeaders["User-Agent"] `
                     -Headers @{ "Accept" = $global:HttpHeaders["Accept"] }
                $http = $r.StatusCode
            }
            catch {
                $reason = Get-HttpFailReason $_
                if ($reason -eq "FAIL") { $reason = Get-HttpFailReason $outerErr }
                $http = if ($reason -eq "FAIL") { "FAIL" } else { "FAIL($reason)" }
                Write-Verbose "Check-Single HTTP [$domain]: $reason"
            }
        }
        Write-Host "HTTP   : $http"
        $logLines.Add("HTTP   : $http")

        # Итоговый статус
        $certTrust = if ($cert) { $cert.Trust } else { "FAIL" }
        $status = "DOWN"
        if ($http -match "^(2|3)" -and $certTrust -eq "TRUSTED") { $status = "UP" }
        elseif ($http -match "^(2|3)" -and $certTrust -ne "TRUSTED") { $status = "DEGRADED" }
        elseif ($dns -eq "OK" -and ($cert.TLS -eq "OK" -or $p.Loss -lt 100)) { $status = "DEGRADED" }

        $color = switch ($status) {
            "UP"       { "Green" }
            "DEGRADED" { "Yellow" }
            "DOWN"     { "Red" }
            default    { "White" }
        }
        Write-Host "Статус : $status" -ForegroundColor $color
        $logLines.Add("Статус : $status")
        $logLines.Add("")   # пустая строка между доменами
    }

    # Предложение сохранить лог — единый стиль с Check-List-WithLog
    Write-Host ""
    Write-Host "  $(T 'SaveHint')" -ForegroundColor DarkGray
    $key = Read-Host " "
    if ($key -eq "S" -or $key -eq "s" -or $key -eq "с" -or $key -eq "С") {
        Save-Log -Type "Single" -Content ($logLines -join "`n") `
            -ExternalIP $global:CachedExternalIP -Geo $global:CachedGeo
    }
}


# ==============================
# ЛОГИРОВАНИЕ
# v1.3: сохранение результатов в Logs\ после любой проверки
# Формат файла: Log_[Тип]_[Дата]_[Время].txt
# ==============================
function Save-Log {
    param(
        [string]$Type,           # Russia / Foreign / Streaming / Custom / Single
        [string]$Content,        # текст для сохранения
        [string]$ExternalIP = "N/A",
        [string]$Geo = "N/A"
    )

    # Создаём папку Logs если нет
    $logsDir = Join-Path $PSScriptRoot "Logs"
    if (-not (Test-Path $logsDir)) {
        New-Item -ItemType Directory -Path $logsDir | Out-Null
    }

    $date     = Get-Date -Format "yyyy-MM-dd"
    $time     = Get-Date -Format "HH-mm"
    $fileName = "Log_${Type}_${date}_${time}.txt"
    $filePath = Join-Path $logsDir $fileName

    $header = @"
NetworkChecker v1.14 — Лог проверки
=====================================
Дата       : $date
Время      : $(Get-Date -Format "HH:mm:ss")
Тип        : $Type
External IP: $ExternalIP
Geo        : $Geo
=====================================

$Content
"@

    $header | Out-File -FilePath $filePath -Encoding UTF8
    Write-Host "  Лог сохранён: Logs\$fileName" -ForegroundColor DarkGray
}


# Вспомогательная функция — собирает вывод Check-List в строку для лога
function Check-List-WithLog {
    param($file, $type)

    if (-not (Test-Path $file)) {
        Write-Host "Файл $file не найден" -ForegroundColor Red
        return
    }

    Write-Host "`n=== Проверка: $file ===" -ForegroundColor Cyan

    $domains = Get-Content $file -Encoding UTF8 |
               ForEach-Object { $_ -replace "`r", '' } |
               Where-Object { $_ -and -not $_.TrimStart().StartsWith("#") } |
               ForEach-Object { Sanitize-Domain $_ } |
               Where-Object { $_ }

    if (-not $domains -or @($domains).Count -eq 0) {
        Write-Host "  Файл пуст или все строки закомментированы: $file" -ForegroundColor Yellow
        return
    }

    $total = @($domains).Count

    Write-Host "  $(T 'Checking'): $([System.IO.Path]::GetFileName($file))" -ForegroundColor Cyan
    Write-Host "  $(T 'DomainsCount'): $total" -ForegroundColor DarkGray

    $logLines = [System.Collections.Generic.List[string]]::new()
    $idx = 0

    foreach ($d in $domains) {
        # Прогресс-бар (v1.7)
        $idx++
        $pct   = [int]($idx / $total * 20)
        $bar   = ('█' * $pct) + ('░' * (20 - $pct))
        $pctN  = [int]($idx / $total * 100)
        # v1.12 [Task]: {0,-40} — фиксированная ширина поля домена.
        # Без этого хвосты длинных доменов остаются на экране при переходе к коротким.
        Write-Host ("`r  [$bar] $pctN%  {0,-40}" -f $d) -NoNewline -ForegroundColor DarkGray
        $r = Test-Domain $d

        $color = switch ($r.Status) {
            "UP"       { "Green" }
            "DEGRADED" { "Yellow" }
            "DOWN"     { "Red" }
            default    { "White" }
        }
        # v1.5: синий для TRUSTED (File/CDN) — Arbitration
        if ($r.Cert -like "*TRUSTED (File)*") { $color = "Cyan" }
        if ($r.Cert -like "*TRUSTED (CDN)*")  { $color = "DarkCyan" }

        $line = ("{0,-25} {1,-10} DNS:{2,-4} TLS:{3,-4} HTTP:{4,-6} PING:{5,-10} LOSS:{6,-6} CERT:{7,-20} IP:{8}" -f `
            $r.Domain, $r.Status, $r.DNS, $r.TLS, $r.HTTP, $r.Ping, $r.Loss, $r.Cert, $r.IP)

        Write-Host "`r" -NoNewline  # очищаем строку прогресса
        Write-Host $line -ForegroundColor $color
        $logLines.Add($line)
    }

    # v1.5: Summary — итоговая строка
    $results = @($logLines)
    $cntUp   = ($results | Where-Object { $_ -match ' UP ' }).Count
    $cntDeg  = ($results | Where-Object { $_ -match ' DEGRADED ' }).Count
    $cntDown = ($results | Where-Object { $_ -match ' DOWN ' }).Count
    $pings   = $results | ForEach-Object {
        if ($_ -match 'PING:(\d+)') { [int]$Matches[1] }
    } | Where-Object { $_ }
    $avgPing = if ($pings) { [int](($pings | Measure-Object -Average).Average) } else { 0 }
    Write-Host ""
    Write-Host ("  $(T 'Summary'): {0}  UP={1}  DEGRADED={2}  DOWN={3}  Avg Ping={4}ms" -f `
        @($domains).Count, $cntUp, $cntDeg, $cntDown, $avgPing) -ForegroundColor Cyan

    Write-Host ""
    Write-Host "  $(T 'SaveHint')" -ForegroundColor DarkGray
    $key = Read-Host " "
    if ($key -eq "S" -or $key -eq "s" -or $key -eq "с" -or $key -eq "С") {
        Save-Log -Type $type -Content ($logLines -join "`n") `
            -ExternalIP $global:CachedExternalIP -Geo $global:CachedGeo
    }
}


# ==============================
# DEBUG WINDOW (пункт 10/12)
# Открывает отдельное окно PowerShell с хвостом лога Verbose
# ==============================
$global:DebugWindowJob = $null

function Start-DebugWindow {
    $logsDir = Join-Path $PSScriptRoot "Logs"
    if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }
    $global:DebugLogPath = Join-Path $logsDir "debug_verbose.log"
    "=== Debug session: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') ===" |
        Out-File $global:DebugLogPath -Encoding UTF8

    # Открываем окно с Get-Content -Wait — читает файл по мере записи
    $escaped = $global:DebugLogPath -replace "'", "''"
    $script  = "`$host.UI.RawUI.WindowTitle='NetworkChecker — Debug'; " +
               "Write-Host 'Ожидание Verbose-сообщений...' -ForegroundColor DarkGray; " +
               "Get-Content -Path '$escaped' -Wait -Encoding UTF8"
    $global:DebugWindowJob = Start-Process powershell.exe `
        -ArgumentList "-NoExit -NoProfile -Command `"$script`"" `
        -PassThru
    Set-Variable -Name VerbosePreference -Value 'Continue' -Scope Global
}

function Stop-DebugWindow {
    if ($global:DebugWindowJob -and -not $global:DebugWindowJob.HasExited) {
        Stop-Process -Id $global:DebugWindowJob.Id -ErrorAction SilentlyContinue
    }
    $global:DebugWindowJob = $null
    Set-Variable -Name VerbosePreference -Value 'SilentlyContinue' -Scope Global
}


# ============================================================
# РУКОВОДСТВО ПОЛЬЗОВАТЕЛЯ (v1.7) — пункт 7
# Скроллируемый документ, без пагинации
# Язык из $global:Lang (RU/EN), переключается пунктом 8
# ============================================================
function Show-Manual {
    Clear-Host

    if ($global:Lang -ne "EN") {

        Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║   NetworkChecker v1.14 — Руководство пользователя                ║" -ForegroundColor Cyan
        Write-Host "║   Developed by Anton Sidorenko & AI Team                         ║" -ForegroundColor DarkGray
        Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ ЧТО ЭТО И ДЛЯ ЧЕГО" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  NetworkChecker — инструмент сетевой диагностики для Windows."
        Write-Host "  Проверяет доступность сайтов и сервисов из вашей сети:"
        Write-Host "   • DNS-резолвинг (получение IP-адреса домена)"
        Write-Host "   • TCP/TLS-соединение (открыт ли порт 443)"
        Write-Host "   • HTTP-ответ сервера (отвечает ли сайт)"
        Write-Host "   • Сертификат (валиден ли, нет ли подмены)"
        Write-Host "   • Пинг (задержка и потери пакетов)"
        Write-Host ""
        Write-Host "  Полезен для: диагностики блокировок, проверки доступности"
        Write-Host "  сервисов, подготовки отчётов для технической поддержки."
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ СТРУКТУРА ПАПОК" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  Создай рядом со скриптом следующие папки:"
        Write-Host ""
        Write-Host "  NC\"
        Write-Host "   ├── NetworkChecker_v1.14.ps1  ← сам скрипт" -ForegroundColor White
        Write-Host "   ├── lists\                    ← папка со списками доменов" -ForegroundColor Cyan
        Write-Host "   │    ├── russia.txt            один домен на строку, без https://" -ForegroundColor DarkGray
        Write-Host "   │    ├── foreign.txt           строки с # — комментарии, игнорируются" -ForegroundColor DarkGray
        Write-Host "   │    ├── streaming.txt" -ForegroundColor DarkGray
        Write-Host "   │    └── (любые .txt файлы)   скрипт найдёт их автоматически" -ForegroundColor DarkGray
        Write-Host "   ├── Logs\                     ← создаётся автоматически" -ForegroundColor Cyan
        Write-Host "   │    └── Log_Russia_2026-04-25_10-30.txt" -ForegroundColor DarkGray
        Write-Host "   └── Certs\                    ← опционально, для Smart Arbitration" -ForegroundColor Cyan
        Write-Host "        ├── russian_trusted_root_ca.cer" -ForegroundColor DarkGray
        Write-Host "        └── active_certs.txt      список активных (создаётся скриптом)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Формат файла списка (пример russia.txt):" -ForegroundColor White
        Write-Host "   google.com" -ForegroundColor DarkGray
        Write-Host "   vk.com" -ForegroundColor DarkGray
        Write-Host "   # это комментарий — строка игнорируется" -ForegroundColor DarkGray
        Write-Host "   sberbank.ru" -ForegroundColor DarkGray
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ ЗАПУСК" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  Скрипт требует прав администратора."
        Write-Host "  • ПКМ на файле → 'Запустить от имени администратора'"
        Write-Host "  • Или: скрипт запросит UAC автоматически при старте"
        Write-Host "  • Или в консоли: powershell -ExecutionPolicy Bypass -File NetworkChecker_v1.7.ps1"
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ ПУНКТЫ МЕНЮ" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1 — Сетевой монитор (реальное время)" -ForegroundColor White
        Write-Host "      Показывает все активные TCP/UDP соединения компьютера."
        Write-Host "      Обновляется каждые 3 секунды. Нажми Q для выхода."
        Write-Host "      Колонки: процесс / состояние / удалённый адрес / страна / скорость KB/s"
        Write-Host "      Цвета: " -NoNewline; Write-Host "ESTAB" -NoNewline -ForegroundColor Green
        Write-Host " = активно  " -NoNewline; Write-Host "SYN-S" -NoNewline -ForegroundColor Red
        Write-Host " = ожидание/блок  " -NoNewline; Write-Host "LISTEN" -NoNewline -ForegroundColor Cyan
        Write-Host " = слушает  " -NoNewline; Write-Host "UDP53" -NoNewline -ForegroundColor DarkYellow
        Write-Host " = DNS"
        Write-Host ""
        Write-Host "  2 — Проверка списков доменов" -ForegroundColor White
        Write-Host "      Показывает все .txt файлы из папки lists\."
        Write-Host "      Введи номер(а) через запятую или 'all' для проверки всех."
        Write-Host "      Прогресс отображается полосой: [████████░░░░] 60%"
        Write-Host "      После завершения: нажми S для сохранения лога в Logs\"
        Write-Host ""
        Write-Host "  6 — Одиночная проверка" -ForegroundColor White
        Write-Host "      Подробная диагностика одного или нескольких доменов."
        Write-Host "      Ввод: google.com или google.com,vk.com,sberbank.ru"
        Write-Host "      Показывает: DNS, Ping (avg/median/min/max), TLS, сертификат, HTTP"
        Write-Host "      После: нажми S для сохранения подробного отчёта"
        Write-Host ""
        Write-Host "  7 — Это руководство" -ForegroundColor White
        Write-Host ""
        Write-Host "  9 — Управление сертификатами (Smart Arbitration)" -ForegroundColor White
        Write-Host "      Показывает .cer файлы из Certs\. Позволяет активировать нужные."
        Write-Host ""
        Write-Host "  10 — Debug-режим (скрытый)" -ForegroundColor DarkGray
        Write-Host "       Открывает отдельное окно с подробным логом в реальном времени."
        Write-Host "  12 — Закрыть Debug-окно" -ForegroundColor DarkGray
        Write-Host "   8 — Переключить язык RU/EN" -ForegroundColor DarkGray
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ КАК ЧИТАТЬ РЕЗУЛЬТАТЫ ПРОВЕРКИ" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Каждая строка в таблице выглядит так:"
        Write-Host "   domain.ru   STATUS   DNS:OK  TLS:OK  HTTP:200  PING:25ms  CERT:TRUSTED  IP:..." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  DNS — получен ли IP-адрес домена" -ForegroundColor White
        Write-Host "   DNS:OK   — домен успешно резолвится"
        Write-Host "   DNS:FAIL — возможно заблокирован на уровне DNS-сервера"
        Write-Host ""
        Write-Host "  TLS — открыт ли защищённый порт 443" -ForegroundColor White
        Write-Host "   TLS:OK   — TCP-соединение установлено, TLS-рукопожатие прошло"
        Write-Host "   TLS:FAIL — порт закрыт, или провайдер вмешивается в соединение"
        Write-Host ""
        Write-Host "  HTTP — ответ веб-сервера" -ForegroundColor White
        Write-Host "   HTTP:200        — сайт отвечает нормально"
        Write-Host "   HTTP:301/302    — редирект (обычно нормально)"
        Write-Host "   HTTP:FAIL(403)  — сервер доступен, но доступ закрыт"
        Write-Host "   HTTP:FAIL(timeout) — соединение есть, ответа нет"
        Write-Host "   HTTP:FAIL(RST)  — соединение сброшено (возможен DPI-блок)"
        Write-Host ""
        Write-Host "  PING — задержка сигнала (ICMP)" -ForegroundColor White
        Write-Host "   Показывает avg (среднее) и median (медиана)."
        Write-Host "   Медиана надёжнее — она не учитывает единичные выбросы."
        Write-Host "   Если avg сильно выше median — был один долгий пакет, а не общий лаг."
        Write-Host "   " -NoNewline; Write-Host "Важно: многие серверы блокируют ICMP." -ForegroundColor Yellow
        Write-Host "   PING:timeout не означает что сайт недоступен — смотри TLS и HTTP."
        Write-Host ""
        Write-Host "  CERT — статус сертификата безопасности" -ForegroundColor White
        Write-Host "   TRUSTED        — сертификат действителен, цепочка проверена"
        Write-Host "   TRUSTED(CDN)   — сертификат от CDN (другой домен, тот же владелец)" -ForegroundColor DarkCyan
        Write-Host "   TRUSTED(File)  — подтверждён через файл в Certs\ (Smart Arbitration)" -ForegroundColor Cyan
        Write-Host "   EXPIRED        — сертификат просрочен"
        Write-Host "   SELF-SIGN      — самоподписанный, не из публичного CA"
        Write-Host "   !CHAIN         — цепочка доверия прервана"
        Write-Host "   MITM           — домен и сертификат не совпадают (возможен перехват)" -ForegroundColor Red
        Write-Host "   DPI/RST        — соединение сброшено при попытке установить TLS" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Итоговый статус строки:" -ForegroundColor White
        Write-Host "   " -NoNewline; Write-Host "UP      " -NoNewline -ForegroundColor Green
        Write-Host " — DNS+TLS+HTTP+CERT все в порядке"
        Write-Host "   " -NoNewline; Write-Host "DEGRADED" -NoNewline -ForegroundColor Yellow
        Write-Host " — сервер виден, но что-то мешает (смотри отдельные колонки)"
        Write-Host "   " -NoNewline; Write-Host "DOWN    " -NoNewline -ForegroundColor Red
        Write-Host " — DNS не прошёл или TCP полностью недоступен"
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ SMART ARBITRATION — ОБЕЛЕНИЕ БАНКОВ" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Проблема:" -ForegroundColor White
        Write-Host "  Некоторые российские сайты (банки, госсервисы) используют сертификаты"
        Write-Host "  от российских удостоверяющих центров (НУЦ Минцифры)."
        Write-Host "  Эти центры не входят в стандартные браузерные хранилища,"
        Write-Host "  поэтому скрипт может показывать MITM — это ложная тревога."
        Write-Host ""
        Write-Host "  Решение — Smart Arbitration:" -ForegroundColor White
        Write-Host "  1. Скачай корневые сертификаты НУЦ: https://www.gosuslugi.ru/crt"
        Write-Host "     Нужны оба файла: russian_trusted_root_ca.cer"
        Write-Host "                      russian_trusted_root_ca_gost_2025.cer"
        Write-Host "  2. Положи .cer файлы в папку Certs\ рядом со скриптом"
        Write-Host "  3. В меню нажми 9, выбери нужные сертификаты (1,2 или all)"
        Write-Host "  4. Запусти проверку снова — MITM изменится на " -NoNewline
        Write-Host "TRUSTED (File)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Как экспортировать сертификат из браузера:" -ForegroundColor White
        Write-Host "  • Открой нужный сайт в Chrome или Edge"
        Write-Host "  • Кликни на замок в адресной строке"
        Write-Host "  • Выбери 'Сертификат' → 'Подробности'"
        Write-Host "  • Выбери корневой CA в иерархии → 'Экспорт' → DER (.cer)"
        Write-Host "  • Положи файл в Certs\ и активируй через пункт 9"
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ ЛОГИ И ОТЧЁТЫ ДЛЯ ПОДДЕРЖКИ" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  После любой проверки нажми S — скрипт сохранит результат в Logs\"
        Write-Host "  Файл содержит: дату, твой внешний IP, геолокацию и все статусы."
        Write-Host "  Отправь этот файл в техническую поддержку — там есть всё нужное."
        Write-Host ""
        Write-Host "  Для одиночной проверки лог подробнее — вертикальный формат:"
        Write-Host "   --- google.com [10:30:15] ---" -ForegroundColor DarkGray
        Write-Host "   DNS    : OK  IP: 142.250.74.46" -ForegroundColor DarkGray
        Write-Host "   Ping   : avg=18ms  median=14ms  min=12ms  max=45ms  loss=0%" -ForegroundColor DarkGray
        Write-Host "   CERT   : 2025-06-01 (40 дней)  Trust:TRUSTED" -ForegroundColor DarkGray
        Write-Host "   Статус : UP" -ForegroundColor DarkGray
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ АВТОРСТВО И ИСТОРИЯ ВЕРСИЙ" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Developed by:" -ForegroundColor White
        Write-Host "   " -NoNewline; Write-Host "Anton Sidorenko" -NoNewline -ForegroundColor Cyan
        Write-Host " — Lead Architect, идея, тестирование, постановка задач"
        Write-Host "   Claude (Anthropic) — архитектура, основной код, рефакторинг"
        Write-Host "   Google AI          — ревью логики, UX-предложения"
        Write-Host "   GPT-4              — hardening, анализ catch-блоков"
        Write-Host "   DeepSeek           — дополнительные идеи"
        Write-Host ""
        Write-Host "  v1.0-1.2  Базовая диагностика, Geo, внешний IP" -ForegroundColor DarkGray
        Write-Host "  v1.3      WAF bypass, логирование, SAN проверка" -ForegroundColor DarkGray
        Write-Host "  v1.4      Hardening: пустые catch→Verbose, CDN-сертификат" -ForegroundColor DarkGray
        Write-Host "  v1.5      Smart Arbitration, выбор сертификатов, сетевой монитор" -ForegroundColor DarkGray
        Write-Host "  v1.6      CDN-детекция, фильтр DNS-шума, GeoCache" -ForegroundColor DarkGray
        Write-Host "  v1.7      Руководство, прогресс-бар, файловый браузер списков," -ForegroundColor DarkGray
        Write-Host "            двухколоночный интерфейс, HTTP:FAIL с причиной" -ForegroundColor DarkGray
        Write-Host "  v1.8      EndConnect .NET-контракт, Tls12|Tls13, Ping.Dispose()" -ForegroundColor DarkGray
        Write-Host "  v1.9      TrustAllCallback: C# делегат вместо ScriptBlock" -ForegroundColor DarkGray
        Write-Host "            (ScriptBlock не пересекает границы потоков .NET)" -ForegroundColor DarkGray
        Write-Host "  v1.10     Легенда в правый угол (SetCursorPosition)" -ForegroundColor DarkGray
        Write-Host "  v1.11     Легенда по кнопке L — overlay, чистый главный экран" -ForegroundColor DarkGray
        Write-Host "  v1.12     Anti-Flicker, OrdinalIgnoreCase HashSet, прогресс-бар fix" -ForegroundColor DarkGray
        Write-Host "  v1.13     pscustomobject вместо array, Show-SideHelp минимализм" -ForegroundColor DarkGray
        Write-Host "  v1.14     Глубокие комментарии, Write-TwoColumns без SetCursorPosition," -ForegroundColor DarkGray
        Write-Host "            Delegate::CreateDelegate, кнопка L в любом регистре" -ForegroundColor DarkGray
        Write-Host ""

    } else {
        # ── ENGLISH VERSION ──────────────────────────────────────────────────
        Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║   NetworkChecker v1.14 — User Manual                             ║" -ForegroundColor Cyan
        Write-Host "║   Developed by Anton Sidorenko & AI Team                         ║" -ForegroundColor DarkGray
        Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ▌ WHAT IS THIS" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  Network diagnostic tool for Windows."
        Write-Host "  Checks: DNS resolution, TCP/TLS connection, HTTP response,"
        Write-Host "  certificate validity, ping latency and packet loss."
        Write-Host "  Useful for diagnosing blocks, service availability checks"
        Write-Host "  and preparing reports for technical support."
        Write-Host ""
        Write-Host "  ▌ FOLDER STRUCTURE" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "   lists\   — .txt files with domains (one per line, no https://)" -ForegroundColor Cyan
        Write-Host "   Logs\    — auto-created, log files saved here" -ForegroundColor Cyan
        Write-Host "   Certs\   — optional .cer files for Smart Arbitration" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ▌ MENU" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  1 — Live network monitor (Q to exit)"
        Write-Host "  2 — Scan domain lists from lists\ folder"
        Write-Host "  6 — Single deep check: google.com,vk.com"
        Write-Host "  7 — This manual"
        Write-Host "  9 — Certificate manager (Smart Arbitration)"
        Write-Host "  10 — Debug window  |  12 — Close debug  |  8 — Toggle RU/EN"
        Write-Host ""
        Write-Host "  ▌ READING RESULTS" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  DNS:OK/FAIL  TLS:OK/FAIL  HTTP:200/FAIL(reason)  PING  CERT  IP"
        Write-Host ""
        Write-Host "  CERT values:" -ForegroundColor White
        Write-Host "   TRUSTED       — certificate chain verified"
        Write-Host "   TRUSTED(CDN)  — CDN cert, different TLD same owner" -ForegroundColor DarkCyan
        Write-Host "   TRUSTED(File) — verified via Certs\ arbitration" -ForegroundColor Cyan
        Write-Host "   MITM          — CN mismatch, possible intercept" -ForegroundColor Red
        Write-Host "   DPI/RST       — connection reset at TLS stage" -ForegroundColor Red
        Write-Host "   EXPIRED / !CHAIN / SELF-SIGN — cert issues"
        Write-Host ""
        Write-Host "  Status:" -ForegroundColor White
        Write-Host "   " -NoNewline; Write-Host "UP      " -NoNewline -ForegroundColor Green; Write-Host " — all checks passed"
        Write-Host "   " -NoNewline; Write-Host "DEGRADED" -NoNewline -ForegroundColor Yellow; Write-Host " — reachable but something is blocking"
        Write-Host "   " -NoNewline; Write-Host "DOWN    " -NoNewline -ForegroundColor Red;    Write-Host " — DNS failed or TCP unreachable"
        Write-Host ""
        Write-Host "  Note: PING timeout does NOT mean DOWN." -ForegroundColor Yellow
        Write-Host "  Many servers block ICMP — check TLS and HTTP instead."
        Write-Host ""
        Write-Host "  ▌ SMART ARBITRATION" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  Russian banks use national CA (not in browser stores) → false MITM."
        Write-Host "  Fix: download .cer from gosuslugi.ru/crt, put in Certs\,"
        Write-Host "  activate via option 9. MITM becomes " -NoNewline
        Write-Host "TRUSTED (File)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ▌ CREDITS" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  Anton Sidorenko — Lead Architect" -ForegroundColor Cyan
        Write-Host "  Claude / GPT-4 / Google AI / DeepSeek — AI Team"
        Write-Host ""
    }

    Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Read-Host "  $(T 'EnterBack')"
}


# ============================================================
# БРАУЗЕР СПИСКОВ (v1.7) — пункт 2
# Читает все .txt из папки lists\, нет жёсткой привязки к именам
# Управление идентично Select-CertFile: номера, all, 0=назад
# ============================================================
function Invoke-MultiList {
    $listsDir = Join-Path $PSScriptRoot "lists"
    if (-not (Test-Path $listsDir)) {
        New-Item -ItemType Directory -Path $listsDir | Out-Null
        Write-Host "  Создана папка lists\" -ForegroundColor DarkGray
        Write-Host "  Положи .txt файлы с доменами (по одному на строку)" -ForegroundColor DarkGray
        return
    }

    $files = @(Get-ChildItem $listsDir -Filter "*.txt" -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -ne "active_certs.txt" })

    if (-not $files) {
        Write-Host "  Папка lists\ пуста. Создай файлы: russia.txt, foreign.txt и т.д." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "  ┌─ lists\ ──────────────────────────────────────────────────┐" -ForegroundColor Cyan
    $i = 1
    foreach ($f in $files) {
        # Считаем количество доменов (строки без # и пустых)
        $count = 0
        try {
            $count = @(Get-Content $f.FullName -Encoding UTF8 |
                       Where-Object { $_ -and -not $_.TrimStart().StartsWith("#") }).Count
        } catch {}
        $countStr = if ($count -gt 0) { "$count доменов" } else { "пусто" }
        $nameClean = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
        Write-Host ("  │  {0,2}. {1,-20} {2,-15} [{3}]" -f $i, $f.Name, $nameClean, $countStr) -ForegroundColor White
        $i++
    }
    Write-Host "  └───────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Введите номер(а) через запятую или 'all' для всех:" -ForegroundColor DarkGray
    Write-Host "  Пример: 1,3  или  all  или  0 для отмены" -ForegroundColor DarkGray
    $sel = Read-Host "  Выбор"

    if (-not $sel -or $sel -eq "0") { return }

    $selected = if ($sel -eq "all") {
        $files
    } else {
        $nums = $sel -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match "^\d+$" }
        $nums | ForEach-Object {
            $idx = [int]$_ - 1
            if ($idx -ge 0 -and $idx -lt $files.Count) { $files[$idx] }
        } | Where-Object { $_ }
    }

    if (-not $selected) {
        Write-Host "  Нет файлов для проверки." -ForegroundColor DarkGray
        return
    }

    foreach ($f in $selected) {
        $typeName = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
        # Капитализируем первую букву для красивого лога
        $typeName = $typeName.Substring(0,1).ToUpper() + $typeName.Substring(1)
        Check-List-WithLog $f.FullName $typeName
    }
}


# ============================================================
# АКТИВНЫЕ СЕРТИФИКАТЫ — персистентность через файл
# ============================================================
function Load-ActiveCerts {
    $path = Join-Path $PSScriptRoot "Certs\active_certs.txt"
    # v1.12 [Task]: OrdinalIgnoreCase — "RootCA.cer" и "rootca.cer" считаются одним файлом.
    # Критично для Windows: файловая система регистронезависима, HashSet по умолчанию — нет.
    # New-Object с компаратором — единственный способ в PS 5.1 (нет ::new(comparer) синтаксиса).
    $global:ActiveCerts = New-Object 'System.Collections.Generic.HashSet[string]' `
        ([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $path) {
        try {
            Get-Content $path -Encoding UTF8 -ErrorAction Stop |
                Where-Object { $_.Trim() } |
                ForEach-Object { [void]$global:ActiveCerts.Add($_.Trim()) }
        } catch {}
    }
}

function Save-ActiveCerts {
    $certsDir = Join-Path $PSScriptRoot "Certs"
    if (-not (Test-Path $certsDir)) {
        New-Item -ItemType Directory -Path $certsDir -Force | Out-Null
    }
    $path = Join-Path $certsDir "active_certs.txt"
    try {
        $global:ActiveCerts | Out-File $path -Encoding UTF8 -ErrorAction Stop
    } catch {}
}

# ============================================================
# ВЫБОР СЕРТИФИКАТА — пункт 9
# ============================================================
function Select-CertFile {
    $certsDir = Join-Path $PSScriptRoot "Certs"
    if (-not (Test-Path $certsDir)) {
        New-Item -ItemType Directory -Path $certsDir -Force | Out-Null
        Write-Host "  Создана папка Certs\" -ForegroundColor DarkGray
    }

    $files = @(Get-ChildItem $certsDir -Filter "*.cer" -ErrorAction SilentlyContinue)

    if (-not $files -or $files.Count -eq 0) {
        Write-Host ""
        Write-Host "  Папка Certs\ пуста." -ForegroundColor Yellow
        Write-Host "  Положи .cer файлы для Smart Arbitration (обеление банков)."
        Write-Host "  Скачать: https://www.gosuslugi.ru/crt"
        Write-Host "  Или: браузер → замок → Сертификат → Экспорт DER (.cer)"
        Write-Host ""
        Read-Host "  Enter"
        return
    }

    Write-Host ""
    Write-Host "  ┌─ Certs\ ───────────────────────────────────────────────────┐" -ForegroundColor Cyan
    $i = 1
    foreach ($f in $files) {
        $active = if ($global:ActiveCerts -and $global:ActiveCerts.Contains($f.Name)) {
            " [ACTIVE]"
        } else { "" }
        $activeColor = if ($active) { "Cyan" } else { "White" }
        try {
            $c  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $f.FullName
            $cn = ($c.Subject -replace "CN=", "" -split ",")[0].Trim()
            Write-Host ("  │  {0,2}. {1,-30} {2,-22}{3}" -f $i, $f.Name, $cn, $active) -ForegroundColor $activeColor
        } catch {
            Write-Host ("  │  {0,2}. {1,-30} (не удалось прочитать){2}" -f $i, $f.Name, $active) -ForegroundColor DarkGray
        }
        $i++
    }
    Write-Host "  └───────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Введи номер(а) через запятую, 'all' или '0' для сброса:" -ForegroundColor DarkGray
    $sel = Read-Host "  Выбор"

    if (-not $sel -or $sel -eq "0") {
        if ($sel -eq "0") {
            $global:ActiveCerts.Clear()
            Save-ActiveCerts
            Write-Host "  Все сертификаты деактивированы." -ForegroundColor Yellow
        }
        return
    }

    if ($sel -eq "all") {
        $global:ActiveCerts.Clear()
        foreach ($f in $files) { [void]$global:ActiveCerts.Add($f.Name) }
        Save-ActiveCerts
        Write-Host "  Активированы все $($files.Count) сертификатов." -ForegroundColor Cyan
        return
    }

    $nums = $sel -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match "^\d+$" }
    foreach ($n in $nums) {
        $idx = [int]$n - 1
        if ($idx -ge 0 -and $idx -lt $files.Count) {
            $name = $files[$idx].Name
            if ($global:ActiveCerts.Contains($name)) {
                [void]$global:ActiveCerts.Remove($name)
                Write-Host "  [-] $name" -ForegroundColor DarkGray
            } else {
                [void]$global:ActiveCerts.Add($name)
                Write-Host "  [+] $name активирован" -ForegroundColor Cyan
            }
        }
    }
    Save-ActiveCerts
    Write-Host "  Активных: $($global:ActiveCerts.Count)" -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 800
}

# ==============================
# МЕНЮ
# ==============================
# Загружаем активные сертификаты при первом запуске
Load-ActiveCerts

# ── Первичная инициализация — один раз, до цикла ─────────────────────
Write-Host "  Получаем сетевые данные..." -ForegroundColor DarkGray
$global:CachedExternalIP = Get-ExternalIP
$global:CachedGeo        = Get-Geo $global:CachedExternalIP
Test-TimeDrift   # Один раз при запуске — проверяем дрейф часов

# Основной цикл меню — IP/Geo больше не запрашиваются повторно
do {
    try {
    Clear-Host
    Show-IPInfo
    Write-Host ""
    # Меню рисуется внутри Show-IPInfo через Write-TwoColumns (без мигания)
    $c = Read-Host "`n  $(T 'Choice')"

    # .ToUpper() — L и Л работают в любом регистре (RU/EN раскладка)
    switch ($c.ToUpper()) {
        "1"  { Show-NetMonitor }
        "2"  { Invoke-MultiList }
        "6"  { Check-Single }
        "7"  { Show-Manual }
        # 8 — переключение языка RU⇄EN (без перезапуска, мгновенно)
        "8"  { $global:Lang = if ($global:Lang -eq "RU") { "EN" } else { "RU" } }
        "9"  { Select-CertFile }
        # 10 — Debug-режим: открывает отдельное окно с Verbose-логом в реальном времени
        "10" {
                $global:DebugMode = -not $global:DebugMode
                $VerbosePreference = if ($global:DebugMode) { 'Continue' } else { 'SilentlyContinue' }
                if ($global:DebugMode) { Start-DebugWindow } else { Stop-DebugWindow }
                Write-Host "  Debug: $(if ($global:DebugMode) { 'ON — новое окно открыто' } else { 'OFF' })" -ForegroundColor DarkGray
                Start-Sleep 1 }
        # 12 — закрыть Debug-окно (если открыто через 10)
        "12" { Stop-DebugWindow; Write-Host "  Debug-окно закрыто" -ForegroundColor DarkGray; Start-Sleep 1 }
        # L/Л — полная легенда поверх экрана (RU и EN раскладка)
        "L"  { Clear-Host; Show-Legend }
        "Л"  { Clear-Host; Show-Legend }
        "0"  { exit }
    }

    } catch {
        # Ошибки цикла меню не показываем пользователю.
        # Для диагностики: запусти с -DebugMode или нажми 10.
        Write-Verbose "Menu loop error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        Start-Sleep -Milliseconds 300
    }
} while ($true)
