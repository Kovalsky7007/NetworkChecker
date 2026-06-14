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
#  v1.14.2 Maintenance — фикс «плывущего» интерфейса [Claude]:
#        — Format-Box: рамки рисуются программно, границы больше не расходятся
#          (легенда и браузеры lists\/Certs\ собирались вручную и плыли на 1-2 симв.)
#        — Главное меню сужено: LeftW 38→36, легенда 42 → итого 78 столбцов.
#          Раньше 80-81 → на консоли шириной 80 строки переносились (главный «плыв»)
#        — Браузеры lists\ и Certs\: строки получили правую границу │ (были открыты)
#        — FIX: удалён дубль function Show-Legend (вторая перекрывала первую)
#        — FIX: мёртвый код Show-SideHelp (~170 строк, нигде не вызывался) удалён
#        — FIX: имя файла в Руководстве v1.7.ps1/v1.14.ps1 → v1_14.ps1 (как на диске)
#  v1.14.3 Сетевой монитор + легенда [Claude]:
#        — Монитор: анти-мерцание (SetCursorPosition вместо Clear-Host каждый тик),
#          курсор больше не прыгает при автообновлении
#        — Монитор: сортировка (S), фильтр/исключение (F: Все/Активные/Без LISTEN/
#          Внешние), пауза (P); список обрезается по высоте окна, не уезжает
#        — Меню: кнопка L переключает легенду вкл/выкл (а не overlay). Выкл —
#          чистое одноколоночное меню, Geo/IP видны полностью
# ============================================================

param(
    [switch]$DebugMode,  # Запуск с -DebugMode включает Verbose-лог (Debug-окно)
    [string]$RunList,    # Авто-режим: имя файла из lists\ (или 'all') для проверки без меню
    [switch]$Quiet       # Тихий режим для планировщика: без интерактива, лог пишется в Logs\
)

# ============================================================
# ВЕРСИЯ — единый источник истины. Меняй ТОЛЬКО здесь при релизе.
# Используется в меню, шапках отчётов, логах и Руководстве.
# (В комментариях-истории версии оставлены как есть — это хронология.)
# ============================================================
$script:Version    = "1.14.8"
$script:VersionTag = "v$script:Version"

# Если передан флаг -DebugMode при запуске — активируем Verbose-вывод сразу.
# FIX: раньше выставлялся только $VerbosePreference, а $global:DebugMode оставался
# $null — из-за этого метка [DEBUG] в меню не показывалась, а пункт 10
# переключался «от пустого значения». Синхронизируем глобальный флаг сразу.
$global:DebugMode = [bool]$DebugMode
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
        # FIX: пробрасываем параметры при повышении прав, иначе они терялись при UAC.
        $fwd = ""
        if ($DebugMode) { $fwd += " -DebugMode" }
        if ($RunList)   { $fwd += " -RunList `"$RunList`"" }
        if ($Quiet)     { $fwd += " -Quiet" }
        Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$PSCommandPath`"$fwd" -Verb RunAs -ErrorAction Stop
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
# v1.14.3: показывать ли легенду в правой колонке меню (кнопка L переключает).
# Off — чистое одноколоночное меню (и Geo/IP видны полностью, без обрезки).
$global:ShowLegend = $true
$global:T = @{
    RU = @{
        MenuTitle    = "NetworkChecker $script:VersionTag — Master Release"
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
        PingPrompt = "Количество пингов для медианы [по умолчанию 10]:"
        PingInput  = "Количество (Enter = 10)"
        StatusLbl  = "Статус"
        VerdictLbl = "Вывод"
        DownDNS    = "DOWN (DNS не прошёл)"
        ListPrompt = "Введите номер(а) через запятую или 'all' для всех:"
        ListHint   = "Пример: 1,3  или  all  или  0 для отмены"
        Cancel     = "Выбор"
        Pinging    = "Пингую"
        PingTimes  = "раз..."
        PingDone   = " готово"
        Days       = "дней"
        MitmWarn1  = "  ⚠ MITM: Сертификат не совпадает с доменом!"
        MitmWarn2  = "    Возможно: подмена провайдером или антивирус перехватывает трафик"
        LogSaved   = "  Лог сохранён: Logs\"
    }
    EN = @{
        MenuTitle    = "NetworkChecker $script:VersionTag — Master Release"
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
        PingPrompt = "Number of pings for the median [default 10]:"
        PingInput  = "Count (Enter = 10)"
        StatusLbl  = "Status"
        VerdictLbl = "Verdict"
        DownDNS    = "DOWN (DNS failed)"
        ListPrompt = "Enter number(s) separated by commas or 'all':"
        ListHint   = "Example: 1,3  or  all  or  0 to cancel"
        Cancel     = "Choice"
        Pinging    = "Pinging"
        PingTimes  = "times..."
        PingDone   = " done"
        Days       = "days"
        MitmWarn1  = "  ⚠ MITM: certificate does not match the domain!"
        MitmWarn2  = "    Possibly ISP spoofing or antivirus intercepting traffic"
        LogSaved   = "  Log saved: Logs\"
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
    if (-not $raw) { return '' }
    $raw = $raw -replace "`r", ''        # CRLF fix — убираем \r от Windows line endings
    $raw = $raw.Trim()
    $raw = $raw -replace '^[a-zA-Z][a-zA-Z0-9+\.\-]*://', ''  # схема http(s):// ftp:// и т.п.
    $raw = $raw -replace '^[:/]+', ''    # v1.14.3: битый ввод вида "://google.com" или "//host"
    $raw = $raw -replace '/.*$', ''      # убираем path после домена
    $raw = $raw -replace ':\d+$', ''     # убираем :порт
    $raw = $raw.Trim().Trim('/')
    # v1.14.3: финальная валидация — домен должен содержать точку и только
    # допустимые символы. Иначе мусор из списков (":", "-") уходил в DNS-резолв.
    if ($raw -notmatch '\.' -or $raw -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\.\-]*[a-zA-Z0-9])?$') {
        return ''
    }
    return $raw
}


# ==============================
# ВНЕШНИЙ IP
# ==============================
# "ms" только к числовому значению; для timeout/N/A — без единиц измерения.
function Format-Ms { param($v); if ("$v" -match '^\d') { "$v ms" } else { "$v" } }

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
function Get-NetSpeed {
    # Возвращает хэш processName.ToLower() → KB/s. Сейчас всегда пустой —
    # монитор показывает "-" в колонке KB/s, и это корректно (см. док.
    # «Известные ограничения»). Реальный per-process трафик доступен только
    # через ETW/perf-счётчики, которые слишком медленны для 3-секундного тика.
    #
    # Прежняя версия каждый тик перебирала ВСЕ процессы и складывала WorkingSet64
    # в глобальный хеш, который нигде не читался — лишняя работа без результата.
    # Оставлена честная заглушка; точку расширения см. в BUGS_AND_FIXES.md.
    return @{}
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
# DNS-СЕРВЕРЫ (через кого резолвим)
# v1.14.6: показываем, какие DNS прописаны на активном интерфейсе. Полезно, когда
# домен резолвится на «странный» IP (напр. заглушку) — видно, виноват ли DNS.
# Известные публичные резолверы подписываем (Google/Cloudflare/...).
# ==============================
function Get-DnsServers {
    $known = @{
        "8.8.8.8"="Google"; "8.8.4.4"="Google"; "1.1.1.1"="Cloudflare"; "1.0.0.1"="Cloudflare"
        "9.9.9.9"="Quad9"; "208.67.222.222"="OpenDNS"; "77.88.8.8"="Yandex"; "77.88.8.1"="Yandex"
        "94.140.14.14"="AdGuard"; "94.140.15.15"="AdGuard"
    }
    try {
        $idx = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
               Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex
        $srv = (Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses
        if (-not $srv) {
            $srv = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                    Where-Object { $_.ServerAddresses }).ServerAddresses
        }
        $srv = @($srv | Select-Object -Unique | Where-Object { $_ -and $_ -ne "127.0.0.1" })
        if (-not $srv -or $srv.Count -eq 0) { return "N/A" }
        return (($srv | ForEach-Object {
            if ($known.ContainsKey($_)) { "$_ ($($known[$_]))" } else { $_ }
        }) -join ", ")
    } catch { return "N/A" }
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
# ==============================
# СОВПАДЕНИЕ ИМЕНИ СЕРТИФИКАТА С ДОМЕНОМ (v1.14.5)
# Корректная проверка hostname: CN + все DNS-имена из SAN, с правилами wildcard
# (*.example.com покрывает ровно ОДИН лейбл слева). SAN читаем по OID 2.5.29.17
# и берём значение после '=' — метка ("DNS Name"/"DNS-имя") локализована, а само
# имя нет, поэтому работает на любой локали Windows.
# ==============================
function Test-HostnameMatch {
    param(
        [string]$Domain,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )
    $dom = $Domain.ToLower().TrimEnd('.')
    $names = New-Object System.Collections.Generic.List[string]

    if ($Cert.Subject -match 'CN=([^,]+)') { [void]$names.Add($Matches[1].Trim()) }

    $san = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if ($san) {
        foreach ($part in ($san.Format($false) -split ',')) {
            $v = $part.Trim()
            if ($v -match '=(.+)$') { $v = $Matches[1].Trim() }   # снимаем локализованную метку
            if ($v -match '\.' -and $v -match '^[*A-Za-z0-9.\-]+$') { [void]$names.Add($v) }
        }
    }

    foreach ($n in $names) {
        $name = $n.ToLower().TrimEnd('.')
        if ($name -eq $dom) { return $true }
        if ($name.StartsWith('*.')) {
            $base = $name.Substring(2)
            if ($dom -eq $base) { return $true }
            if ($dom.EndsWith('.' + $base)) {
                $left = $dom.Substring(0, $dom.Length - $base.Length - 1)
                if ($left -and $left -notmatch '\.') { return $true }  # wildcard = один лейбл
            }
        }
    }
    return $false
}

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
        CdnCert  = $false   # серт «того же владельца» (база CN = база домена) → TRUSTED (CDN)
        AltName  = $false   # валидный публичный серт, но на ЧУЖОЕ имя → TRUSTED* (CDN или редирект)
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

        # 5. ВЕРДИКТ ПО СЕРТИФИКАТУ (v1.14.5 — точная логика)
        # Опираемся на ДВА независимых факта:
        #   $hostMatch — имя в сертификате реально покрывает домен (CN/SAN/wildcard);
        #   $chainOK   — цепочка строится до доверенного корня в хранилище Windows.
        # MITM (перехват) ставим ТОЛЬКО когда имя НЕ совпало И цепочка НЕ доверена —
        # т.е. подсунут недоверенный серт на чужое имя (стаб РКН, антивирус с своим CA).
        # Публично доверенный серт на другое имя подделать невозможно → это CDN/
        # фронтинг (yastatic.net через *.yandex.net), а НЕ перехват.
        #
        # Раньше MITM ставился по одному несовпадению имени, ДО проверки цепочки —
        # отсюда массовые ложные MITM на CDN-доменах Яндекса/Google.
        # [Google AI] идея MITM-детекции сохранена, но усилена доверием цепочки [Claude v1.14.5].

        $hostMatch = Test-HostnameMatch -Domain $Domain -Cert $cert

        # CDN «тот же владелец, другой TLD»: yandex.ru ↔ CN=*.yandex.com
        if (-not $hostMatch -and $cert.Subject -match "CN=\*?\.?([a-z0-9\-]+)\.[a-z]+") {
            $cnBase   = $Matches[1].ToLower()
            $domParts = $Domain.Split('.')
            $domBase  = if ($domParts.Count -ge 2) { $domParts[-2].ToLower() } else { $Domain.ToLower() }
            if ($cnBase -eq $domBase) {
                $hostMatch = $true
                $result.CdnCert = $true
                Write-Verbose "[$Domain] CDN cert: база CN '$cnBase' = база домена '$domBase'"
            }
        }

        # Доверие цепочки (revocation off — медленно и часто режется DPI).
        # [GPT] ChainStatus — конкретная причина, а не просто FAIL.
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chainOK = $chain.Build($cert)
        $isSelfSigned = ($cert.Subject -eq $cert.Issuer)
        $chainReason  = "!CHAIN"
        foreach ($s in $chain.ChainStatus) {
            Write-Verbose "[$Domain] ChainStatus: $($s.Status) — $($s.StatusInformation)"
            switch ($s.Status) {
                "PartialChain"  { $chainReason = "PartialChain" }
                "UntrustedRoot" { $chainReason = "UntrustedRoot" }
                "NotTimeValid"  { $chainReason = "Expired" }
                "Revoked"       { $chainReason = "Revoked" }
            }
        }
        Write-Verbose "[$Domain] hostMatch=$hostMatch chainOK=$chainOK selfSigned=$isSelfSigned"

        # Просрочен — приоритетнее остальных вердиктов
        if ($result.DaysLeft -lt 0) {
            $result.Status = "OK"; $result.Trust = "EXPIRED"; $result.Reason = "Cert expired"
            return $result
        }

        $result.Status = "OK"
        if ($hostMatch) {
            if ($chainOK) {
                # Имя совпало + цепочка доверена — всё чисто.
                $result.Trust = "TRUSTED"; $result.Reason = "OK"
            } else {
                # Имя верное, но корень не доверен: нац.УЦ / корп.прокси / самоподпись —
                # это НЕ подмена идентичности. Сначала арбитраж по Certs\.
                $arb = Test-CertArbitration -Domain $Domain -CertSubject $cert.Subject
                if     ($arb)          { $result.Trust = $arb;       $result.Reason = "OK" }
                elseif ($isSelfSigned) { $result.Trust = "SELF-SIGN"; $result.Reason = "Self-signed" }
                else                   { $result.Trust = "!CHAIN";    $result.Reason = $chainReason }
            }
        } else {
            # Имя НЕ совпало.
            $arb = Test-CertArbitration -Domain $Domain -CertSubject $cert.Subject
            if ($arb) {
                $result.Trust = $arb; $result.Reason = "OK"
            } elseif ($chainOK) {
                # Публично доверенный серт на ЧУЖОЕ имя. Перехвата нет (такой серт не
                # подделать), но это может быть как настоящий CDN, так и DNS-редирект
                # на стаб-заглушку (напр. блок Meta на одном IP). Помечаем TRUSTED* —
                # «валидный серт, другое имя; проверь IP и HTTP».
                $result.AltName = $true
                $result.Trust = "TRUSTED"; $result.Reason = "valid cert, name mismatch"
            } else {
                # Недоверенный серт + чужое имя → реальный перехват.
                $result.Trust = "MITM"; $result.Reason = "MITM"
                $result.Error = "Untrusted cert for different host (intercept)"
            }
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
# ВЕРДИКТ ПРОСТЫМ ЯЗЫКОМ (v1.14.6)
# Переводит сырьё DNS/TLS/HTTP/CERT в одну понятную фразу + класс для цвета:
#   OK    — доступен (зелёный)
#   MINOR — достижим, но не отдаёт страницу (404/403/429) или 503 — НЕ блок (циан)
#   BLOCK — реальная проблема: DPI/RST, TLS-блок, заглушка-редирект, MITM (красный)
#   DOWN  — нет DNS-записи (часто это норма для apex/инфра-доменов) (серый)
# Возвращает @{ Label; Class }.
# ==============================
function Get-Verdict {
    param($dns, $tls, [string]$http, $cert)
    $ru = ($global:Lang -ne "EN")
    $L = if ($ru) {
        @{ ok="Доступен"; nopage="Без страницы"; dpi="Блок DPI/RST"; tlsb="Блок TLS";
           stub="Заглушка"; mitm="MITM-перехват"; htmo="Блок (timeout)"; nodns="Нет DNS-записи";
           down="Недоступен"; herr="HTTP-ошибка" }
    } else {
        @{ ok="Reachable"; nopage="No page"; dpi="DPI/RST block"; tlsb="TLS block";
           stub="Stub redirect"; mitm="MITM intercept"; htmo="Block (timeout)"; nodns="No DNS record";
           down="Unreachable"; herr="HTTP error" }
    }

    if ($dns -ne "OK") { return @{ Label=$L.nodns; Class="DOWN" } }

    $trust  = if ($cert) { "$($cert.Trust)" }  else { "FAIL" }
    $reason = if ($cert) { "$($cert.Reason)" } else { "" }
    $alt    = ($cert -and $cert.AltName)

    if ($trust -eq "MITM") { return @{ Label=$L.mitm; Class="BLOCK" } }

    # HTTP реально отдал страницу (2xx/3xx) → домен доступен, ТОЧКА. Проверка
    # сертификата идёт отдельным соединением и может сфлапать по таймауту
    # (как soundcloud: HTTP:200, но TLS-проба отвалилась) — это не блок.
    if ($http -match '^(2|3)') { return @{ Label=$L.ok; Class="OK" } }

    # HTTP не отдался — разбираемся почему именно.
    if ($tls -ne "OK") {
        if ($reason -match "DPI|RST")     { return @{ Label=$L.dpi;  Class="BLOCK" } }
        if ($reason -match "Timeout|TCP") { return @{ Label=$L.tlsb; Class="BLOCK" } }
        return @{ Label=$L.tlsb; Class="BLOCK" }
    }

    # HTTP не отдался, но TLS живой
    if ($alt)                  { return @{ Label=$L.stub; Class="BLOCK" } }   # валид.серт на чужое имя + фейл = редирект-заглушка
    if ($http -match "RST")     { return @{ Label=$L.dpi;  Class="BLOCK" } }
    if ($http -match "timeout") { return @{ Label=$L.htmo; Class="BLOCK" } }
    if ($http -match "TLS-err") { return @{ Label=$L.tlsb; Class="BLOCK" } }
    if ($http -match "403|404|429|503") { return @{ Label=$L.nopage; Class="MINOR" } }  # достижим, просто не страница
    return @{ Label=$L.herr; Class="MINOR" }
}

function Get-VerdictColor {
    param([string]$class)
    switch ($class) {
        "OK"    { "Green" }
        "MINOR" { "DarkCyan" }
        "BLOCK" { "Red" }
        "DOWN"  { "DarkGray" }
        default { "White" }
    }
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
        elseif ($cert.AltName)                { "TRUSTED*" }       # валид. серт, чужое имя
        elseif ($cert.Trust -eq "TRUSTED")    { "TRUSTED" }
        elseif ($cert.Trust -like "TRUSTED *") { $cert.Trust }  # TRUSTED (File)
        elseif ($cert.Trust -eq "FAIL")       { "FAIL ($($cert.Reason))" }
        else                                  { $cert.Trust }
    } else { "N/A" }

    # "ms" добавляем только к числовому пингу; у timeout/N/A единицы не нужны.
    $pingStr = if ("$pingAvg" -match '^\d') { "$pingAvg ms" } else { "$pingAvg" }

    # Вердикт простым языком (см. Get-Verdict)
    $v = Get-Verdict $dns $tls $http $cert

    return [PSCustomObject]@{
        Domain  = $domain
        IP      = $ip
        DNS     = $dns
        TLS     = $tls
        HTTP    = $http
        Ping    = $pingStr
        Loss    = "${loss}%"
        Cert    = $certLabel
        Status  = $status
        Verdict = $v.Label
        VClass  = $v.Class
    }
}


# ==============================
# ТАБЛИЧНАЯ СТРОКА + ИТОГ (v1.14.6)
# Единый формат для всех проверок: первая колонка — вердикт простым языком,
# дальше техсырьё DNS/TLS/HTTP/PING/LOSS/CERT/IP для тех, кому нужны детали.
# ==============================
function Format-ResultRow {
    param($r)
    # Вердикт -14, HTTP -13 (вмещает FAIL(TLS-err)), CERT -20 — колонка IP не «плывёт».
    ("{0,-25} {1,-14} DNS:{2,-4} TLS:{3,-4} HTTP:{4,-13} PING:{5,-10} LOSS:{6,-6} CERT:{7,-20} IP:{8}" -f `
        $r.Domain, $r.Verdict, $r.DNS, $r.TLS, $r.HTTP, $r.Ping, $r.Loss, $r.Cert, $r.IP)
}

function Write-ResultSummary {
    # Итог по понятным классам, а не по сырым UP/DEGRADED/DOWN.
    param([array]$Rows)
    $ru = ($global:Lang -ne "EN")
    $ok=0; $mi=0; $bl=0; $dw=0
    foreach ($x in $Rows) {
        switch ($x.VClass) { "OK" {$ok++} "MINOR" {$mi++} "BLOCK" {$bl++} "DOWN" {$dw++} }
    }
    $pings = $Rows | ForEach-Object { if ("$($_.Ping)" -match '^(\d+(\.\d+)?)') { [double]$Matches[1] } } | Where-Object { $_ }
    $avg = if ($pings) { [int](($pings | Measure-Object -Average).Average) } else { 0 }

    Write-Host ""
    Write-Host ("  $(T 'Summary'): {0}   " -f $Rows.Count) -NoNewline -ForegroundColor Cyan
    Write-Host ($(if($ru){"Доступно:"}else{"OK:"}) + $ok + " ")        -NoNewline -ForegroundColor Green
    Write-Host ($(if($ru){"Без стр.:"}else{"No-page:"}) + $mi + " ")    -NoNewline -ForegroundColor DarkCyan
    Write-Host ($(if($ru){"Блок:"}else{"Block:"}) + $bl + " ")          -NoNewline -ForegroundColor Red
    Write-Host ($(if($ru){"Нет DNS:"}else{"No-DNS:"}) + $dw)            -NoNewline -ForegroundColor DarkGray
    Write-Host ("   Avg Ping={0}ms" -f $avg) -ForegroundColor Cyan
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
# FORMAT-BOX (v1.14.2) — программная отрисовка рамок
# Каждая строка дополняется пробелами до ширины $Inner, поэтому
# правая граница всегда стоит на одном месте независимо от длины
# текста. Это устраняет «плывущий» интерфейс — раньше рамки
# рисовались вручную и легко расходились на 1-2 символа.
#   $Title  — заголовок в верхней рамке (может быть пустым)
#   $Rows   — массив @{T="текст";C="Color"}; @{Sep=$true} даёт разделитель
#   $Inner  — внутренняя ширина (между │ и │); полная ширина = $Inner + 2
# Возвращает массив pscustomobject {T;C} — формат, понятный Write-TwoColumns.
# ============================================================
function Format-Box {
    param(
        [string]$Title = "",
        [array]$Rows,
        [int]$Inner = 40,
        [string]$Border = "Yellow"
    )
    $box  = New-Object System.Collections.Generic.List[object]
    $dash = [char]0x2500   # ─
    $head = if ($Title) { "$dash $Title " } else { "$dash$dash" }
    if ($head.Length -gt $Inner) { $head = $head.Substring(0, $Inner) }
    $top  = [string][char]0x250C + $head + ([string]$dash * ($Inner - $head.Length)) + [char]0x2510
    $box.Add([pscustomobject]@{ T = $top; C = $Border })
    foreach ($r in $Rows) {
        if ($r.Sep) {
            $box.Add([pscustomobject]@{ T = [string][char]0x251C + ([string]$dash * $Inner) + [char]0x2524; C = $Border })
            continue
        }
        $txt = [string]$r.T
        if ($txt.Length -gt $Inner) { $txt = $txt.Substring(0, $Inner) }
        $col = if ($r.C) { [string]$r.C } else { "White" }
        $box.Add([pscustomobject]@{ T = [string][char]0x2502 + $txt.PadRight($Inner) + [char]0x2502; C = $col })
    }
    $box.Add([pscustomobject]@{ T = [string][char]0x2514 + ([string]$dash * $Inner) + [char]0x2518; C = $Border })
    return $box
}



# ============================================================
# GLOBAL:LEGENDDATA — единый источник данных для легенды
# Показывается в правой колонке главного меню (Show-IPInfo), если включена
# кнопкой L ($global:ShowLegend). Собирается через Format-Box — границы ровные.
# v1.14 [Claude]: добавлен SELF-SIGN, заметка про антивирусный MITM.
# RU/EN — переключается глобальным $global:Lang (пункт 8 меню).
# ============================================================
$global:LegendData = @{
    RU = @(Format-Box -Title "ЛЕГЕНДА" -Inner 40 -Border "Yellow" -Rows @(
        @{T=" Вывод (1-я колонка):"; C="Yellow"}
        @{T="  Доступен      — работает"; C="Green"}
        @{T="  Без страницы  — достижим, нет стр."; C="DarkCyan"}
        @{T="  Блок …        — DPI/TLS/заглушка/MITM"; C="Red"}
        @{T="  Нет DNS-записи— не резолвится"; C="DarkGray"}
        @{Sep=$true}
        @{T=" CERT — статус сертификата:"; C="Yellow"}
        @{T="  TRUSTED       — цепочка доверия OK"; C="White"}
        @{T="  TRUSTED(CDN)  — CDN-серт, другой TLD"; C="DarkCyan"}
        @{T="  TRUSTED(File) — арбитраж через Certs\"; C="Cyan"}
        @{T="  TRUSTED* — валид.серт, чужое имя"; C="DarkCyan"}
        @{T="  MITM     — недовер. серт на чужое имя"; C="Red"}
        @{T="  DPI/RST  — RST на SNI-рукопожатии"; C="Red"}
        @{T="  EXPIRED  — сертификат просрочен"; C="DarkGray"}
        @{T="  !CHAIN   — цепочка доверия сломана"; C="DarkGray"}
        @{T="  SELF-SIGN— самоподписанный серт"; C="DarkGray"}
        @{Sep=$true}
        @{T=" Столбцы результата:"; C="Yellow"}
        @{T="  DNS  — резолвинг домена в IP"; C="White"}
        @{T="  TLS  — TCP + TLS-рукопожатие"; C="White"}
        @{T="  HTTP — код ответа (200/301/FAIL)"; C="White"}
        @{T="  PING — задержка мс (avg/median)"; C="White"}
        @{T="  LOSS — потери пакетов, %"; C="White"}
        @{Sep=$true}
        @{T=" ! PING timeout не равен DOWN"; C="DarkGray"}
        @{T="   банки и госсайты блокируют ICMP"; C="DarkGray"}
        @{T=" ! MITM может быть антивирусом"; C="DarkGray"}
        @{T="   Kaspersky/ESET перехватывают TLS"; C="DarkGray"}
    )) + @([pscustomobject]@{T="  L — скрыть/показать легенду"; C="DarkGray"})

    EN = @(Format-Box -Title "LEGEND" -Inner 40 -Border "Yellow" -Rows @(
        @{T=" Verdict (col 1):"; C="Yellow"}
        @{T="  Reachable     — works"; C="Green"}
        @{T="  No page       — reachable, no page"; C="DarkCyan"}
        @{T="  Block …       — DPI/TLS/stub/MITM"; C="Red"}
        @{T="  No DNS record — not resolving"; C="DarkGray"}
        @{Sep=$true}
        @{T=" CERT — certificate status:"; C="Yellow"}
        @{T="  TRUSTED       — chain verified OK"; C="White"}
        @{T="  TRUSTED(CDN)  — CDN cert, other TLD"; C="DarkCyan"}
        @{T="  TRUSTED(File) — Certs\ arbitration"; C="Cyan"}
        @{T="  TRUSTED* — valid cert, other name"; C="DarkCyan"}
        @{T="  MITM     — untrusted cert, wrong host"; C="Red"}
        @{T="  DPI/RST  — reset at SNI handshake"; C="Red"}
        @{T="  EXPIRED  — certificate expired"; C="DarkGray"}
        @{T="  !CHAIN   — trust chain broken"; C="DarkGray"}
        @{T="  SELF-SIGN— self-signed cert"; C="DarkGray"}
        @{Sep=$true}
        @{T=" Result columns:"; C="Yellow"}
        @{T="  DNS  — domain to IP resolution"; C="White"}
        @{T="  TLS  — TCP + TLS handshake"; C="White"}
        @{T="  HTTP — response (200/301/FAIL)"; C="White"}
        @{T="  PING — latency ms (avg/median)"; C="White"}
        @{T="  LOSS — packet loss, %"; C="White"}
        @{Sep=$true}
        @{T=" ! PING timeout is not DOWN"; C="DarkGray"}
        @{T="   banks and gov sites block ICMP"; C="DarkGray"}
        @{T=" ! MITM may be your antivirus"; C="DarkGray"}
        @{T="   Kaspersky/ESET intercept TLS"; C="DarkGray"}
    )) + @([pscustomobject]@{T="  L — toggle legend"; C="DarkGray"})
}




# ============================================================
# SHOW-IPINFO — главное меню
# v1.7 [Claude+Anton]: двухколоночный рендер Write-TwoColumns.
#   Левая колонка  = шапка (IP/Geo/версия) + пункты меню (16 строк).
#   Правая колонка = краткая легенда из $global:LegendData (29 строк).
# v1.10: попытка SetCursorPosition — убрана в v1.14 (ломала скролл
#         и позиционирование при любом изменении размера окна).
# v1.14.2 [Claude]: LeftW=36, легенда 42 -> всего 78 столбцов. Раньше было
#   38 + 42/43 = 80-81: на консоли шириной 80 строки переносились и
#   интерфейс «плыл». Теперь общая ширина гарантированно меньше 80.
# Нет HTTP-запросов — только кэш ($global:CachedExternalIP/CachedGeo).
# ============================================================
function Show-IPInfo {
    # Читаем только кэш — IP/Geo запрашиваются один раз при старте скрипта
    $local    = Get-LocalIP
    $external = if ($global:CachedExternalIP) { $global:CachedExternalIP } else { "..." }
    $geo      = if ($global:CachedGeo)        { $global:CachedGeo        } else { "..." }
    $dns      = if ($global:CachedDns)        { $global:CachedDns        } else { "..." }
    $isRU     = ($global:Lang -ne "EN")
    $debug    = if ($global:DebugMode) { " [DEBUG]" } else { "" }
    # Количество активных сертификатов — рядом с пунктом 9
    $certs    = if ($global:ActiveCerts -and $global:ActiveCerts.Count -gt 0) {
                    " [$($global:ActiveCerts.Count) акт.]"
                } else { "" }
    $lg   = if ($global:ShowLegend) { if ($isRU) { "вкл" } else { "on" } } else { if ($isRU) { "выкл" } else { "off" } }
    $hint = if ($isRU) { "  [L-легенда:$lg  8-язык  10-debug]" } else { "  [L-legend:$lg  8-lang  10-debug]" }

    # ── Левая колонка: шапка + меню ──────────────────────────────────────
    # 16 строк: 3 заголовка + 3 сепаратора + 3 IP + 6 пунктов + 1 hint
    # Ширина строк <= 36 символов (LeftW=36) — не обрезается
    $menuLines = if ($isRU) { @(
        [pscustomobject]@{T="====================================";C="Cyan"}
        [pscustomobject]@{T="  NetworkChecker $script:VersionTag$debug";C="Yellow"}
        [pscustomobject]@{T="  Anton Sidorenko & AI Team";C="DarkGray"}
        [pscustomobject]@{T="====================================";C="Cyan"}
        [pscustomobject]@{T="  Local IP   : $local";C="White"}
        [pscustomobject]@{T="  External IP: $external";C="White"}
        [pscustomobject]@{T="  Geo        : $geo";C="White"}
        [pscustomobject]@{T="  DNS        : $dns";C="White"}
        [pscustomobject]@{T="====================================";C="Cyan"}
        [pscustomobject]@{T="  1 - Сетевой монитор";C="White"}
        [pscustomobject]@{T="  2 - Проверка доменов (lists\)";C="White"}
        [pscustomobject]@{T="  3 - Планировщик задач";C="White"}
        [pscustomobject]@{T="  4 - DNS-проверка (подмена)";C="White"}
        [pscustomobject]@{T="  6 - Одиночная проверка";C="White"}
        [pscustomobject]@{T="  7 - Руководство";C="White"}
        [pscustomobject]@{T="  9 - Сертификаты$certs";C="White"}
        [pscustomobject]@{T="  0 - Выход";C="DarkGray"}
        [pscustomobject]@{T="====================================";C="Cyan"}
        [pscustomobject]@{T=$hint;C="DarkGray"}
    ) } else { @(
        [pscustomobject]@{T="====================================";C="Cyan"}
        [pscustomobject]@{T="  NetworkChecker $script:VersionTag$debug";C="Yellow"}
        [pscustomobject]@{T="  Anton Sidorenko & AI Team";C="DarkGray"}
        [pscustomobject]@{T="====================================";C="Cyan"}
        [pscustomobject]@{T="  Local IP   : $local";C="White"}
        [pscustomobject]@{T="  External IP: $external";C="White"}
        [pscustomobject]@{T="  Geo        : $geo";C="White"}
        [pscustomobject]@{T="  DNS        : $dns";C="White"}
        [pscustomobject]@{T="====================================";C="Cyan"}
        [pscustomobject]@{T="  1 - Network Monitor";C="White"}
        [pscustomobject]@{T="  2 - Domain scan (lists\)";C="White"}
        [pscustomobject]@{T="  3 - Task Scheduler";C="White"}
        [pscustomobject]@{T="  4 - DNS check (spoof)";C="White"}
        [pscustomobject]@{T="  6 - Single check";C="White"}
        [pscustomobject]@{T="  7 - Manual";C="White"}
        [pscustomobject]@{T="  9 - Certificates$certs";C="White"}
        [pscustomobject]@{T="  0 - Exit";C="DarkGray"}
        [pscustomobject]@{T="====================================";C="Cyan"}
        [pscustomobject]@{T=$hint;C="DarkGray"}
    ) }

    # ── Рендер ───────────────────────────────────────────────────────────
    # L (в меню) переключает $global:ShowLegend.
    #   ON  — двухколоночный режим: меню (36) + легенда (42), привязана к правому краю.
    #   OFF — чистое одноколоночное меню во всю ширину (Geo/IP не обрезаются).
    if ($global:ShowLegend) {
        $lang        = if ($isRU) { "RU" } else { "EN" }
        $legendLines = $global:LegendData[$lang]
        Write-TwoColumns -Left $menuLines -Right $legendLines -LeftW 36
    } else {
        foreach ($ln in $menuLines) {
            $c = [string]$ln.C; if ($c -notmatch '^[A-Za-z]+$') { $c = "White" }
            Write-Host $ln.T -ForegroundColor $c
        }
    }
}


function Show-NetMonitor {
    # v1.14.3 [Claude]: переписан рендер.
    #   — Анти-мерцание: один Clear-Host при входе, далее перерисовка через
    #     SetCursorPosition(0,0) с затиранием хвоста. Курсор больше не «прыгает».
    #   — Сортировка (S) и фильтр/исключение (F) переключаются на лету.
    #   — Пауза (P) замораживает автообновление, чтобы спокойно читать список.
    #   — Тело обрезается по высоте окна — длинный список не уезжает за экран.
    $global:GeoCache = @{}
    $ru = ($global:Lang -eq "RU")

    $sortNames   = if ($ru) { @("Состояние","Процесс","Гео","Адрес") }      else { @("State","Process","Geo","Address") }
    $filterNames = if ($ru) { @("Все","Активные","Без LISTEN","Внешние") } else { @("All","Active","No LISTEN","External") }
    $sortMode = 0; $filterMode = 0; $paused = $false
    $rows = @(); $speedMap = @{}
    $prevCount = 0

    try { [Console]::CursorVisible = $false } catch {}
    Clear-Host

    try {
        while ($true) {
            if (-not $paused) {
                # ── Сбор данных ──
                $proc = @{}
                Get-Process | ForEach-Object { $proc[$_.Id] = $_.ProcessName }
                $rawLines = netstat -ano 2>$null
                $rows = $rawLines | ForEach-Object {
                    $line = ($_ -replace '\s+', ' ').Trim()
                    if (-not $line) { return }
                    $f = $line.Split(' ')
                    if ($f.Count -lt 4) { return }
                    $proto = $f[0]
                    if ($proto -ne "TCP" -and $proto -ne "UDP") { return }
                    $local = $f[1]; $remote = $f[2]
                    $state = if ($proto -eq "TCP") { $f[3] } else { "UDP" }
                    $pidRaw = $f[-1]
                    if ($pidRaw -notmatch '^\d+$') { return }
                    $pid_ = [int]$pidRaw
                    $keep = $false
                    if ($proto -eq "TCP" -and $state -in @("ESTABLISHED","SYN_SENT","SYN_RECEIVED","LISTENING")) { $keep = $true }
                    if ($proto -eq "UDP" -and $local -match ':53$') { $keep = $true }
                    if (-not $keep) { return }
                    $remoteIP = if ($remote -match '^(.+):\d+$') { $Matches[1] } else { $remote }
                    $name = if ($proc[$pid_]) { $proc[$pid_] } else { "?" }
                    [PSCustomObject]@{ Process=$name; Proto=$proto; State=$state; Remote=$remote; RemoteIP=$remoteIP; PID=$pid_ }
                } | Where-Object { $_ }
                $rows = @($rows)

                $uniqueIPs = $rows | Select-Object -ExpandProperty RemoteIP -Unique |
                             Where-Object { $_ -and $_ -ne "0.0.0.0" -and $_ -ne "*" }
                foreach ($ip in $uniqueIPs) {
                    if (-not $global:GeoCache.ContainsKey($ip)) { Get-GeoCode $ip | Out-Null }
                }
                $speedMap = Get-NetSpeed
            }

            # ── Фильтр (исключение) ──
            $isLocal = {
                param($ip)
                (-not $ip) -or $ip -eq "0.0.0.0" -or $ip -eq "*" -or $ip -like "127.*" -or
                $ip -like "10.*" -or $ip -like "192.168.*" -or
                $ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.' -or
                $ip -like "*::1*" -or $ip -like "*fe80*"
            }
            $view = switch ($filterMode) {
                1 { $rows | Where-Object { $_.State -in @("ESTABLISHED","SYN_SENT","SYN_RECEIVED") } }
                2 { $rows | Where-Object { $_.State -ne "LISTENING" } }
                3 { $rows | Where-Object { -not (& $isLocal $_.RemoteIP) } }
                default { $rows }
            }
            $view = @($view)

            # ── Сортировка ──
            $rank = @{ "ESTABLISHED"=0; "SYN_SENT"=1; "SYN_RECEIVED"=1; "LISTENING"=2; "UDP"=3 }
            $view = switch ($sortMode) {
                1 { $view | Sort-Object Process, State }
                2 { $view | Sort-Object @{E={ if ($global:GeoCache.ContainsKey($_.RemoteIP)) { $global:GeoCache[$_.RemoteIP] } else { "zz" } }}, Process }
                3 { $view | Sort-Object RemoteIP, Process }
                default { $view | Sort-Object @{E={ $rank[$_.State] }}, Process }
            }
            $view = @($view)

            # ── Счётчики (по всему набору) ──
            $cntEst=0; $cntSyn=0; $cntListen=0; $cntUdp=0
            foreach ($r in $rows) {
                switch ($r.State) {
                    "ESTABLISHED"  { $cntEst++ }
                    "SYN_SENT"     { $cntSyn++ }
                    "SYN_RECEIVED" { $cntSyn++ }
                    "LISTENING"    { $cntListen++ }
                    "UDP"          { $cntUdp++ }
                }
            }

            # ── Сборка кадра ──
            $frame = New-Object System.Collections.Generic.List[object]
            $ts = Get-Date -Format "HH:mm:ss"
            $title = if ($ru) { "Сетевой монитор" } else { "Network Monitor" }
            $pTag = if ($paused) { if ($ru) { "  [ПАУЗА]" } else { "  [PAUSED]" } } else { "" }
            $frame.Add([pscustomobject]@{T="=== $title  $ts ===$pTag"; C="Yellow"})
            $sL = if ($ru) { "Сорт" } else { "Sort" }
            $fL = if ($ru) { "Фильтр" } else { "Filter" }
            $frame.Add([pscustomobject]@{T=("  {0}: {1,-11} {2}: {3}" -f $sL,$sortNames[$sortMode],$fL,$filterNames[$filterMode]); C="DarkCyan"})
            $frame.Add([pscustomobject]@{T=("{0,-18} {1,-6} {2,-22} {3,-4} {4,-7} {5}" -f "Process","State","Remote","Geo","KB/s","PID"); C="DarkGray"})
            $frame.Add([pscustomobject]@{T=("-"*70); C="DarkGray"})

            $winH = try { [Console]::WindowHeight } catch { 30 }
            $maxBody = [Math]::Max(3, $winH - 9)
            $shown = 0
            foreach ($r in $view) {
                if ($shown -ge $maxBody) { break }
                $geo = if ($global:GeoCache.ContainsKey($r.RemoteIP)) { $global:GeoCache[$r.RemoteIP] } else { ".." }
                $kbs = $speedMap[$r.Process.ToLower()]
                $kbStr = if ($kbs -and $kbs -gt 0) { "$kbs" } else { "-" }
                $color = switch ($r.State) {
                    "ESTABLISHED"  { "Green" }
                    "SYN_SENT"     { "Red" }
                    "SYN_RECEIVED" { "Red" }
                    "LISTENING"    { "Cyan" }
                    "UDP"          { "DarkYellow" }
                    default        { "DarkGray" }
                }
                $st = switch ($r.State) {
                    "ESTABLISHED"  { "ESTAB" }
                    "SYN_SENT"     { "SYN-S" }
                    "SYN_RECEIVED" { "SYN-R" }
                    "LISTENING"    { "LISTN" }
                    "UDP"          { "UDP53" }
                    default        { $r.State.Substring(0, [Math]::Min(5, $r.State.Length)) }
                }
                $pn = if ($r.Process.Length -gt 17) { $r.Process.Substring(0,16) + "~" } else { $r.Process }
                $rs = if ($r.Remote.Length  -gt 21) { $r.Remote.Substring(0,20)  + "~" } else { $r.Remote }
                $frame.Add([pscustomobject]@{T=("{0,-18} {1,-6} {2,-22} {3,-4} {4,-7} {5}" -f $pn,$st,$rs,$geo,$kbStr,$r.PID); C=$color})
                $shown++
            }
            $hidden = $view.Count - $shown
            if ($hidden -gt 0) {
                $more = if ($ru) { "  … ещё $hidden (сузьте фильтром F или увеличьте окно)" } else { "  … $hidden more (filter F or grow window)" }
                $frame.Add([pscustomobject]@{T=$more; C="DarkGray"})
            }

            $frame.Add([pscustomobject]@{T=("-"*70); C="DarkGray"})
            $shL = if ($ru) { "Показано" } else { "Shown" }
            $frame.Add([pscustomobject]@{T=("  {0}:{1}/{2}   ESTAB:{3}  SYN:{4}  LISTEN:{5}  UDP:{6}" -f $shL,$view.Count,@($rows).Count,$cntEst,$cntSyn,$cntListen,$cntUdp); C="White"})
            $hint = if ($ru) { "  Q-выход  S-сорт  F-фильтр  P-пауза   (авто 3с)" } else { "  Q-quit  S-sort  F-filter  P-pause   (auto 3s)" }
            $frame.Add([pscustomobject]@{T=$hint; C="DarkGray"})

            # ── Анти-мерцание: рисуем с (0,0), затираем хвост прошлого кадра ──
            $w = try { [Console]::WindowWidth } catch { 80 }
            if ($w -lt 20) { $w = 80 }
            try { [Console]::SetCursorPosition(0,0) } catch { Clear-Host }
            foreach ($ln in $frame) {
                $t = [string]$ln.T
                if ($t.Length -gt $w-1) { $t = $t.Substring(0, $w-1) }
                $c = [string]$ln.C; if ($c -notmatch '^[A-Za-z]+$') { $c = "White" }
                Write-Host $t.PadRight($w-1) -ForegroundColor $c
            }
            for ($i = $frame.Count; $i -lt $prevCount; $i++) { Write-Host (" " * ($w-1)) }
            $prevCount = $frame.Count

            # ── Ожидание тика с мгновенной реакцией на клавиши ──
            $deadline = (Get-Date).AddSeconds(3)
            $redraw = $false
            while (-not $redraw -and (Get-Date) -lt $deadline) {
                if ([Console]::KeyAvailable) {
                    $k = ([Console]::ReadKey($true).KeyChar.ToString()).ToLower()
                    if     ($k -eq 'q' -or $k -eq 'й') { return }
                    elseif ($k -eq 's' -or $k -eq 'ы') { $sortMode   = ($sortMode + 1)   % $sortNames.Count;   $redraw = $true }
                    elseif ($k -eq 'f' -or $k -eq 'а') { $filterMode = ($filterMode + 1) % $filterNames.Count; $redraw = $true }
                    elseif ($k -eq 'p' -or $k -eq 'з') { $paused = -not $paused;                                $redraw = $true }
                }
                if (-not $redraw) { Start-Sleep -Milliseconds 80 }
            }
        }
    }
    finally {
        try { [Console]::CursorVisible = $true } catch {}
        $global:GeoCache = @{}
        Clear-Host
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

    Write-Host "  $(T 'PingPrompt')"
    $countRaw = Read-Host "  $(T 'PingInput')"

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
    $logLines.Add("NetworkChecker $script:VersionTag | SINGLE CHECK REPORT")
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
            Write-Host "$(T 'StatusLbl') : $(T 'DownDNS')" -ForegroundColor Red
            $logLines.Add("$(T 'StatusLbl') : $(T 'DownDNS')")
            $logLines.Add("")
            continue
        }

        Write-Host "$(T 'Pinging') $pingCount $(T 'PingTimes')" -NoNewline
        $p = Get-PingStats $ip -Count $pingCount
        Write-Host "$(T 'PingDone')"
        # v1.7: визуальный блок пинга — медиана выделена как основной показатель
        $pingLine = "Ping   : avg={0}  median={1}  min={2}  max={3}  loss={4}%" -f `
            (Format-Ms $p.Avg), (Format-Ms $p.Median), (Format-Ms $p.Min), (Format-Ms $p.Max), $p.Loss
        Write-Host "Ping   : " -NoNewline
        Write-Host "avg=$(Format-Ms $p.Avg)" -NoNewline -ForegroundColor DarkGray
        Write-Host "  " -NoNewline
        # Медиана — главный показатель (устойчив к выбросам)
        # FIX: try/catch — Median может быть строкой "timeout" когда ICMP заблокирован
        $medColor = "DarkGray"
        try { $medColor = if ([double]$p.Median -lt 50) { "Green" } elseif ([double]$p.Median -lt 150) { "Yellow" } else { "Red" } } catch {}
        Write-Host "median=$(Format-Ms $p.Median)" -NoNewline -ForegroundColor $medColor
        Write-Host "  min=$(Format-Ms $p.Min)  max=$(Format-Ms $p.Max)  loss=$($p.Loss)%" -NoNewline -ForegroundColor DarkGray
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

            $certLine = "CERT   : {0}  ({1} {3})  Trust:{2}" -f $cert.Expiry, $cert.DaysLeft, $cert.Trust, (T 'Days')
            Write-Host $certLine -ForegroundColor $certColor
            Write-Host ("         {0}" -f $cert.Subject)
            $logLines.Add($certLine)
            $logLines.Add("         $($cert.Subject)")

            if ($cert.Trust -eq "MITM") {
                Write-Host (T 'MitmWarn1') -ForegroundColor Red
                Write-Host (T 'MitmWarn2') -ForegroundColor Yellow
                $logLines.Add((T 'MitmWarn1'))
                $logLines.Add((T 'MitmWarn2'))
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

        # Итоговый вывод простым языком (тот же классификатор, что и в таблицах)
        $v     = Get-Verdict $dns $cert.TLS $http $cert
        $color = Get-VerdictColor $v.Class
        Write-Host "$(T 'VerdictLbl') : $($v.Label)" -ForegroundColor $color
        $logLines.Add("$(T 'VerdictLbl') : $($v.Label)")
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


# ============================================================
# DNS-ПРОВЕРКА (v1.14.8) — пункт 4
# Резолвит домен через системный DNS, публичные (1.1.1.1, 8.8.8.8), любые
# КАСТОМНЫЕ серверы — и сравнивает с DoH-ЭТАЛОНОМ (DNS поверх HTTPS, порт 443).
# DoH нельзя прозрачно перехватить на порту 53, поэтому он — «правда». Если
# plaintext-ответ расходится с DoH → это перехват/подмена. Показывает задержку.
# ============================================================
function Get-AviaDns {
    # Массив IPv4 A-записей через plaintext DNS (UDP 53). $server пуст = системный.
    param([string]$domain, [string]$server)
    try {
        $p = @{ Name=$domain; Type='A'; DnsOnly=$true; NoHostsFile=$true; ErrorAction='Stop' }
        if ($server) { $p.Server = $server; $p.QuickTimeout = $true }
        $r = Resolve-DnsName @p
        return ,@($r | Where-Object { $_.Type -eq 'A' } |
                  Select-Object -ExpandProperty IPAddress -Unique | Sort-Object)
    } catch { return ,@() }
}

function Resolve-Doh {
    # Эталон: A-записи через DoH (HTTPS/443) — Google, затем Cloudflare как фолбэк.
    param([string]$domain)
    $eps = @(
        @{ Url = "https://dns.google/resolve?name=$domain&type=A";        Hdr = @{} },
        @{ Url = "https://cloudflare-dns.com/dns-query?name=$domain&type=A"; Hdr = @{ accept = 'application/dns-json' } }
    )
    foreach ($e in $eps) {
        try {
            $r = Invoke-RestMethod $e.Url -Headers $e.Hdr -TimeoutSec 6 -ErrorAction Stop
            $ips = @($r.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data } |
                     Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -Unique | Sort-Object)
            if ($ips.Count -gt 0) { return ,$ips }
        } catch {}
    }
    return ,@()
}

function Show-DnsCheck {
    $ru = ($global:Lang -ne "EN")
    Write-Host ("  === " + $(if($ru){"DNS-проверка (plaintext vs DoH-эталон)"}else{"DNS check (plaintext vs DoH truth)"}) + " ===") -ForegroundColor Cyan
    Write-Host ""
    $inputStr = Read-Host "  $(T 'Domains')"
    if (-not $inputStr) { return }
    $domains = $inputStr -split ',' | ForEach-Object { Sanitize-Domain $_ } | Where-Object { $_ }
    if (-not $domains) { return }

    # Кастомные DNS-серверы (опционально)
    Write-Host ("  " + $(if($ru){"Доп. DNS-серверы через запятую (Enter — только стандартные):"}else{"Extra DNS servers, comma-separated (Enter for defaults):"})) -ForegroundColor DarkGray
    $customRaw = Read-Host "  DNS"
    $customs = @($customRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })

    # Список резолверов: системный + публичные + кастомные
    $resolvers = New-Object System.Collections.Generic.List[object]
    $resolvers.Add(@{ Name = $(if($ru){"Система"}else{"System"}); Server = "" })
    $resolvers.Add(@{ Name = "1.1.1.1"; Server = "1.1.1.1" })
    $resolvers.Add(@{ Name = "8.8.8.8"; Server = "8.8.8.8" })
    foreach ($c in $customs) { $resolvers.Add(@{ Name = $c; Server = $c }) }

    $fmt = {
        param($arr)
        if (-not $arr -or @($arr).Count -eq 0) { return "—" }
        $a = @($arr)
        if ($a.Count -le 3) { return ($a -join ", ") }
        return (($a[0..2] -join ", ") + ", …(+$($a.Count-3))")
    }

    Write-Host ("  " + $(if($ru){"Резолвлю (DoH-эталон + plaintext)..."}else{"Resolving (DoH truth + plaintext)..."})) -ForegroundColor DarkGray
    Write-Host ""

    $log = [System.Collections.Generic.List[string]]::new()
    $log.Add("DNS check $script:VersionTag  $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')")
    $log.Add("Система DNS: $global:CachedDns")
    $log.Add("")

    foreach ($d in @($domains)) {
        $truth = Resolve-Doh $d                       # эталон (DoH)
        $hasTruth = (@($truth).Count -gt 0)

        # plaintext-резолверы с замером задержки
        $rows = foreach ($rv in $resolvers) {
            $sw  = [System.Diagnostics.Stopwatch]::StartNew()
            $ips = Get-AviaDns $d $rv.Server
            $sw.Stop()
            $clean = if ($hasTruth -and @($ips).Count -gt 0) { (@($ips) | Where-Object { $truth -contains $_ }).Count -gt 0 } else { $null }
            [pscustomobject]@{ Name=$rv.Name; Ips=@($ips); Ms=[int]$sw.ElapsedMilliseconds; Clean=$clean }
        }
        $rows = @($rows)

        # Вердикт по домену
        $anyIps    = ($rows | Where-Object { $_.Ips.Count -gt 0 }).Count -gt 0
        $poisoned  = @($rows | Where-Object { $_.Clean -eq $false })
        $cleanOnes = @($rows | Where-Object { $_.Clean -eq $true })

        if (-not $hasTruth) {
            if (-not $anyIps) { $vt = if($ru){"не резолвится нигде"}else{"no resolution anywhere"}; $vc="DarkGray" }
            else { $vt = if($ru){"DoH недоступен — сверка неполная"}else{"DoH unavailable — partial check"}; $vc="Yellow" }
        }
        elseif (-not $anyIps) {
            $vt = if($ru){"блок: plaintext DNS молчит, DoH видит"}else{"block: plaintext silent, DoH resolves"}; $vc="Red"
        }
        elseif ($poisoned.Count -eq 0) {
            $vt = if($ru){"совпадает с DoH (чисто)"}else{"matches DoH (clean)"}; $vc="Green"
        }
        elseif ($cleanOnes.Count -eq 0) {
            $vt = if($ru){"ПЕРЕХВАТ DNS :53 (все plaintext ≠ DoH)"}else{"DNS HIJACK :53 (all plaintext != DoH)"}; $vc="Red"
        }
        else {
            $vt = if($ru){"частичная подмена (часть резолверов врёт)"}else{"partial spoof (some resolvers lie)"}; $vc="Red"
        }

        # Вывод
        Write-Host "  $d" -ForegroundColor Cyan
        Write-Host ("    {0,-14}: {1}" -f "DoH (эталон)", (& $fmt $truth)) -ForegroundColor White
        $log.Add($d); $log.Add("  DoH(эталон) : $(& $fmt $truth)")
        foreach ($row in $rows) {
            $mark = ""; $col = "DarkGray"
            if ($row.Clean -eq $true)  { $col = "Green" }
            if ($row.Clean -eq $false) { $col = "Red"; $mark = if($ru){"  ≠DoH"}else{"  !=DoH"} }
            Write-Host ("    {0,-14}: {1}   ({2} ms){3}" -f $row.Name, (& $fmt $row.Ips), $row.Ms, $mark) -ForegroundColor $col
            $log.Add(("  {0,-12}: {1}  ({2} ms){3}" -f $row.Name, (& $fmt $row.Ips), $row.Ms, $mark))
        }
        Write-Host ("    -> $vt") -ForegroundColor $vc
        Write-Host ""
        $log.Add("  -> $vt"); $log.Add("")
    }

    Write-Host "  $(T 'SaveHint')" -ForegroundColor DarkGray
    $key = Read-Host " "
    if ($key -eq "S" -or $key -eq "s" -or $key -eq "с" -or $key -eq "С") {
        Save-Log -Type "DNS" -Content ($log -join "`n") `
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
NetworkChecker $script:VersionTag — Лог проверки
=====================================
Дата       : $date
Время      : $(Get-Date -Format "HH:mm:ss")
Тип        : $Type
External IP: $ExternalIP
Geo        : $Geo
DNS        : $global:CachedDns
=====================================

$Content
"@

    $header | Out-File -FilePath $filePath -Encoding UTF8
    Write-Host "$(T 'LogSaved')$fileName" -ForegroundColor DarkGray
}


# Вспомогательная функция — собирает вывод Check-List в строку для лога
function Check-List-WithLog {
    param($file, $type, [switch]$AutoSave)

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
    $rows = [System.Collections.Generic.List[object]]::new()
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
        $rows.Add($r)

        $color = Get-VerdictColor $r.VClass
        $line  = Format-ResultRow $r

        Write-Host "`r" -NoNewline  # очищаем строку прогресса
        Write-Host $line -ForegroundColor $color
        $logLines.Add($line)
    }

    Write-ResultSummary $rows

    # AutoSave — для авто-режима (-RunList / Планировщик): сохраняем без запроса.
    if ($AutoSave) {
        Save-Log -Type $type -Content ($logLines -join "`n") `
            -ExternalIP $global:CachedExternalIP -Geo $global:CachedGeo
        return
    }

    Write-Host ""
    Write-Host "  $(T 'SaveHint')" -ForegroundColor DarkGray
    $key = Read-Host " "
    if ($key -eq "S" -or $key -eq "s" -or $key -eq "с" -or $key -eq "С") {
        Save-Log -Type $type -Content ($logLines -join "`n") `
            -ExternalIP $global:CachedExternalIP -Geo $global:CachedGeo
    }
}


# ============================================================
# АВТО-РЕЖИМ + ПЛАНИРОВЩИК ЗАДАЧ (v1.14.4)
# Неинтерактивный прогон списков для Планировщика Windows (schtasks).
# Никаких служб и стороннего ПО — только штатный планировщик.
# ============================================================
function Get-NCTaskName { "NetworkChecker_AutoScan" }

function Invoke-AutoRun {
    # Прогон без меню: $ListName — имя файла из lists\ (с .txt или без) либо 'all'.
    # Лог каждого списка сохраняется в Logs\ автоматически (AutoSave).
    param([string]$ListName)

    $listsDir = Join-Path $PSScriptRoot "lists"
    if (-not (Test-Path $listsDir)) {
        Write-Host "  lists\ не найдена" -ForegroundColor Red
        return
    }
    $files = @(Get-ChildItem $listsDir -Filter "*.txt" -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -ne "active_certs.txt" })

    if ($ListName -and $ListName -ne 'all') {
        $want = $ListName
        if ($want -notlike '*.txt') { $want += '.txt' }
        $files = @($files | Where-Object { $_.Name -ieq $want })
    }
    if (-not $files -or $files.Count -eq 0) {
        Write-Host "  Список '$ListName' не найден в lists\" -ForegroundColor Red
        return
    }

    if (-not $Quiet) {
        Write-Host "  Авто-проверка ($($files.Count) сп.) — $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
    }
    foreach ($f in $files) {
        $typeName = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
        $typeName = $typeName.Substring(0,1).ToUpper() + $typeName.Substring(1)
        Check-List-WithLog $f.FullName $typeName -AutoSave
    }
    if (-not $Quiet) {
        Write-Host "  Готово. Логи: Logs\" -ForegroundColor DarkGray
    }
}

function Manage-Schedule {
    # UI управления задачей Планировщика. Создаёт/удаляет ежедневный авто-скан.
    $ru = ($global:Lang -ne "EN")
    $taskName = Get-NCTaskName

    while ($true) {
        Clear-Host
        Write-Host ("  === " + $(if ($ru){"Планировщик задач"}else{"Task Scheduler"}) + " ===") -ForegroundColor Cyan
        Write-Host ""

        # Текущее состояние задачи
        schtasks /Query /TN $taskName *>$null
        $exists = ($LASTEXITCODE -eq 0)
        if ($exists) {
            Write-Host ("  " + $(if($ru){"Задача создана"}else{"Task installed"}) + ": $taskName") -ForegroundColor Green
            schtasks /Query /TN $taskName /FO LIST 2>$null |
                Where-Object { $_ -match '^(Next Run Time|Schedule|Task To Run|Время следующего|Расписание|Запускаемая)' } |
                ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        } else {
            Write-Host ("  " + $(if($ru){"Задача не создана"}else{"No task installed"})) -ForegroundColor DarkGray
        }

        Write-Host ""
        Write-Host ("  1 - " + $(if($ru){"Создать/пересоздать ежедневный авто-скан"}else{"Create/replace daily auto-scan"})) -ForegroundColor White
        Write-Host ("  2 - " + $(if($ru){"Удалить задачу"}else{"Delete task"})) -ForegroundColor White
        Write-Host ("  0 - " + $(if($ru){"Назад"}else{"Back"})) -ForegroundColor DarkGray
        Write-Host ""
        $sel = Read-Host "  $(T 'Choice')"

        switch ($sel) {
            "1" { Install-ScheduledTask }
            "2" {
                if ($exists) {
                    schtasks /Delete /TN $taskName /F *>$null
                    Write-Host ("  " + $(if($ru){"Задача удалена"}else{"Task deleted"})) -ForegroundColor Yellow
                } else {
                    Write-Host ("  " + $(if($ru){"Нечего удалять"}else{"Nothing to delete"})) -ForegroundColor DarkGray
                }
                Start-Sleep 1
            }
            "0"     { return }
            default { }
        }
    }
}

function Install-ScheduledTask {
    $ru = ($global:Lang -ne "EN")
    $taskName = Get-NCTaskName

    # Какой список гонять
    Write-Host ""
    Write-Host ("  " + $(if($ru){"Какой список проверять? (имя файла из lists\ без .txt, или 'all')"}else{"Which list? (file name from lists\ without .txt, or 'all')"})) -ForegroundColor DarkGray
    $list = Read-Host "  lists\"
    if (-not $list) { $list = "all" }

    # Время запуска (HH:mm)
    Write-Host ("  " + $(if($ru){"Время ежедневного запуска [ЧЧ:ММ, Enter = 09:00]"}else{"Daily run time [HH:mm, Enter = 09:00]"})) -ForegroundColor DarkGray
    $time = Read-Host "  HH:mm"
    if ($time -notmatch '^\d{1,2}:\d{2}$') { $time = "09:00" }

    # Команда запуска: текущий powershell + этот скрипт + авто-режим
    $psExe = (Get-Command powershell.exe).Source
    $tr = "`"$psExe`" -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -RunList `"$list`" -Quiet"

    # /RL HIGHEST — задача стартует с правами администратора (скрипту они нужны).
    # /F — перезаписать, если задача уже есть.
    schtasks /Create /TN $taskName /TR $tr /SC DAILY /ST $time /RL HIGHEST /F *>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host ("  " + $(if($ru){"Задача создана"}else{"Task created"}) + ": $list @ $time") -ForegroundColor Green
        Write-Host ("  " + $(if($ru){"Логи будут в Logs\ после каждого запуска"}else{"Logs will appear in Logs\ after each run"})) -ForegroundColor DarkGray
    } else {
        Write-Host ("  " + $(if($ru){"Не удалось создать задачу (код $LASTEXITCODE)"}else{"Failed to create task (code $LASTEXITCODE)"})) -ForegroundColor Red
    }
    Start-Sleep 2
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

        # Рамка собирается программно (Inner=66) — выравнивание не зависит от
        # длины строки версии (раньше было «прибито» пробелами и ломалось при правке).
        $mW = 66
        Write-Host ("╔" + ([string][char]0x2550 * $mW) + "╗") -ForegroundColor Cyan
        Write-Host ("║" + ("   NetworkChecker $script:VersionTag — Руководство пользователя").PadRight($mW).Substring(0,$mW) + "║") -ForegroundColor Cyan
        Write-Host ("║" + "   Developed by Anton Sidorenko & AI Team".PadRight($mW).Substring(0,$mW) + "║") -ForegroundColor DarkGray
        Write-Host ("╚" + ([string][char]0x2550 * $mW) + "╝") -ForegroundColor Cyan
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
        Write-Host "   ├── NetworkChecker.ps1        ← сам скрипт" -ForegroundColor White
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
        Write-Host "  • Или в консоли: powershell -ExecutionPolicy Bypass -File NetworkChecker.ps1"
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ ПУНКТЫ МЕНЮ" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1 — Сетевой монитор (реальное время)" -ForegroundColor White
        Write-Host "      Показывает все активные TCP/UDP соединения компьютера."
        Write-Host "      Обновляется каждые 3 секунды (без мерцания)."
        Write-Host "      Клавиши: Q — выход, S — сортировка, F — фильтр, P — пауза."
        Write-Host "      Фильтр (F): Все / Активные / Без LISTEN / Только внешние."
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
        Write-Host "      Несколько списков (или 'all') → ОДНА сводная таблица с общим"
        Write-Host "      итогом; повторяющиеся домены проверяются один раз (дедуп)."
        Write-Host "      Один список → подробный разбор именно этого файла."
        Write-Host "      Прогресс отображается полосой: [████████░░░░] 60%"
        Write-Host "      После завершения: нажми S для сохранения лога в Logs\"
        Write-Host ""
        Write-Host "  4 — DNS-проверка (детект подмены/перехвата)" -ForegroundColor White
        Write-Host "      Резолвит домен(ы) через системный/публичные/свои DNS и сверяет"
        Write-Host "      с DoH-эталоном (DNS поверх HTTPS — его не перехватить на порту 53)."
        Write-Host "      plaintext ≠ DoH → перехват/подмена. Можно указать свои DNS-серверы."
        Write-Host "      Показывает задержку: быстрый ответ «1.1.1.1» (2-6мс) = локальный перехват."
        Write-Host "      Отличает DNS-блок от DPI-блока в канале."
        Write-Host ""
        Write-Host "  3 — Планировщик задач (авто-проверка)" -ForegroundColor White
        Write-Host "      Создаёт задачу Windows (schtasks), которая раз в день сама"
        Write-Host "      проверяет выбранный список и пишет отчёт в Logs\ — без участия"
        Write-Host "      пользователя. Никаких служб и стороннего ПО, только штатный"
        Write-Host "      Планировщик. Вручную: -RunList <имя|all> -Quiet"
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
        Write-Host "   L — показать/скрыть легенду в правой колонке меню" -ForegroundColor DarkGray
        Write-Host ""

        # ─────────────────────────────────────────────────────
        Write-Host "  ▌ КАК ЧИТАТЬ РЕЗУЛЬТАТЫ ПРОВЕРКИ" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Каждая строка в таблице выглядит так:"
        Write-Host "   domain.ru   ВЫВОД   DNS:OK  TLS:OK  HTTP:200  PING:25ms  CERT:TRUSTED  IP:..." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  ВЫВОД (1-я колонка) — итог простым языком:" -ForegroundColor White
        Write-Host "   Доступен       — работает (зелёный)"
        Write-Host "   Без страницы   — достижим, но не отдаёт страницу (404/403/429/503)"
        Write-Host "                    — это НЕ блок, просто у домена нет веб-страницы"
        Write-Host "   Блок DPI/RST   — соединение режется (DPI)"
        Write-Host "   Блок TLS       — рукопожатие не проходит (таймаут/сброс)"
        Write-Host "   Заглушка       — валидный серт на чужое имя + фейл = редирект на стаб"
        Write-Host "   MITM-перехват  — недоверенный серт на чужое имя"
        Write-Host "   Нет DNS-записи  — домен не резолвится (часто норма для apex/инфра)"
        Write-Host ""
        Write-Host "  Дальше идёт техсырьё (для деталей):" -ForegroundColor White
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
        Write-Host "   TRUSTED*       — валидный серт, но имя не совпало (CDN или редирект" -ForegroundColor DarkCyan
        Write-Host "                    на стаб — смотри IP и HTTP)" -ForegroundColor DarkCyan
        Write-Host "   EXPIRED        — сертификат просрочен"
        Write-Host "   SELF-SIGN      — самоподписанный, не из публичного CA"
        Write-Host "   !CHAIN         — цепочка доверия прервана"
        Write-Host "   MITM           — недоверенный серт на чужое имя (реальный перехват)" -ForegroundColor Red
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
        Write-Host "  v1.14.2   Format-Box: ровные рамки, фикс «плывущего» меню (78 столбцов)," -ForegroundColor DarkGray
        Write-Host "            удалён дубль Show-Legend и мёртвый Show-SideHelp" -ForegroundColor DarkGray
        Write-Host "  v1.14.3   Монитор: анти-мерцание, сортировка/фильтр/пауза;" -ForegroundColor DarkGray
        Write-Host "            кнопка L переключает легенду (вкл/выкл)" -ForegroundColor DarkGray
        Write-Host "  v1.14.4   Константа версии, локализация EN, авто-режим (-RunList)," -ForegroundColor DarkGray
        Write-Host "            интеграция с Планировщиком задач, фикс -DebugMode" -ForegroundColor DarkGray
        Write-Host "  v1.14.5   Точный вердикт серта: MITM только при недовер. цепочке +" -ForegroundColor DarkGray
        Write-Host "            чужом имени; убраны ложные MITM на CDN; сводная таблица all" -ForegroundColor DarkGray
        Write-Host "  v1.14.6   Колонка-вывод простым языком, приглушены ложные тревоги," -ForegroundColor DarkGray
        Write-Host "            детект заглушки, показ текущих DNS-серверов в шапке" -ForegroundColor DarkGray
        Write-Host "  v1.14.7   DNS-проверка (сравнение резолверов, детект подмены)," -ForegroundColor DarkGray
        Write-Host "            фикс вердикта: HTTP:200 побеждает флап TLS-пробы" -ForegroundColor DarkGray
        Write-Host "  v1.14.8   DNS: DoH-эталон (детект перехвата :53), кастомные DNS," -ForegroundColor DarkGray
        Write-Host "            задержка по каждому резолверу" -ForegroundColor DarkGray
        Write-Host ""

    } else {
        # ── ENGLISH VERSION ──────────────────────────────────────────────────
        $mW = 66
        Write-Host ("╔" + ([string][char]0x2550 * $mW) + "╗") -ForegroundColor Cyan
        Write-Host ("║" + ("   NetworkChecker $script:VersionTag — User Manual").PadRight($mW).Substring(0,$mW) + "║") -ForegroundColor Cyan
        Write-Host ("║" + "   Developed by Anton Sidorenko & AI Team".PadRight($mW).Substring(0,$mW) + "║") -ForegroundColor DarkGray
        Write-Host ("╚" + ([string][char]0x2550 * $mW) + "╝") -ForegroundColor Cyan
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
        Write-Host "  1 — Live network monitor (Q-quit S-sort F-filter P-pause)"
        Write-Host "  2 — Scan domain lists ('all'/multi = one combined table, dedup)"
        Write-Host "  3 — Task Scheduler: daily auto-scan (schtasks, no service)"
        Write-Host "  4 — DNS check: plaintext vs DoH truth, custom servers, latency"
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
        Write-Host "   TRUSTED*      — valid cert but name mismatch (CDN or redirect)" -ForegroundColor DarkCyan
        Write-Host "   MITM          — untrusted cert for wrong host (real intercept)" -ForegroundColor Red
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
function Check-CombinedLists {
    # Сводная проверка нескольких списков ОДНОЙ таблицей. Домены объединяются и
    # дедуплицируются между файлами (регистр игнорируется), проверяются один раз,
    # выводятся единым списком + один общий итог. Используется при выборе 'all'
    # или нескольких номеров в пункте 2.
    param([array]$Files)
    $ru = ($global:Lang -ne "EN")

    # Уникальные домены, порядок сохраняем, повтор между списками отбрасываем
    $seen    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $domains = New-Object System.Collections.Generic.List[string]
    foreach ($f in $Files) {
        try {
            Get-Content $f.FullName -Encoding UTF8 |
                ForEach-Object { $_ -replace "`r", '' } |
                Where-Object { $_ -and -not $_.TrimStart().StartsWith("#") } |
                ForEach-Object { Sanitize-Domain $_ } |
                Where-Object { $_ } |
                ForEach-Object { if ($seen.Add($_)) { [void]$domains.Add($_) } }
        } catch {}
    }
    if ($domains.Count -eq 0) {
        Write-Host ("  " + $(if($ru){"Нет доменов для проверки"}else{"No domains to check"})) -ForegroundColor Yellow
        return
    }

    $listNames = ($Files | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }) -join ", "
    Write-Host ""
    Write-Host ("  === " + $(if($ru){"Сводная проверка"}else{"Combined scan"}) + " ($($Files.Count)) ===") -ForegroundColor Cyan
    Write-Host ("  $listNames") -ForegroundColor DarkGray
    Write-Host ("  $(T 'DomainsCount'): $($domains.Count)") -ForegroundColor DarkGray

    $logLines = [System.Collections.Generic.List[string]]::new()
    $rows = [System.Collections.Generic.List[object]]::new()
    $total = $domains.Count
    $idx = 0
    foreach ($d in $domains) {
        $idx++
        $pct  = [int]($idx / $total * 20)
        $bar  = ('█' * $pct) + ('░' * (20 - $pct))
        $pctN = [int]($idx / $total * 100)
        Write-Host ("`r  [$bar] $pctN%  {0,-40}" -f $d) -NoNewline -ForegroundColor DarkGray
        $r = Test-Domain $d
        $rows.Add($r)

        $color = Get-VerdictColor $r.VClass
        $line  = Format-ResultRow $r
        Write-Host "`r" -NoNewline
        Write-Host $line -ForegroundColor $color
        $logLines.Add($line)
    }

    Write-ResultSummary $rows

    Write-Host ""
    Write-Host "  $(T 'SaveHint')" -ForegroundColor DarkGray
    $key = Read-Host " "
    if ($key -eq "S" -or $key -eq "s" -or $key -eq "с" -or $key -eq "С") {
        Save-Log -Type "Combined" -Content ($logLines -join "`n") `
            -ExternalIP $global:CachedExternalIP -Geo $global:CachedGeo
    }
}

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
        # v1.14.2: строка дополняется до 59 символов и закрывается │ — рамка ровная
        $row = ("  {0,2}. {1,-22} {2,-16}[{3}]" -f $i, $f.Name, $nameClean, $countStr)
        if ($row.Length -gt 59) { $row = $row.Substring(0, 59) }
        Write-Host ("  │" + $row.PadRight(59) + "│") -ForegroundColor White
        $i++
    }
    Write-Host "  └───────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  $(T 'ListPrompt')" -ForegroundColor DarkGray
    Write-Host "  $(T 'ListHint')" -ForegroundColor DarkGray
    $sel = Read-Host "  $(T 'Cancel')"

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

    $selected = @($selected)
    # Несколько списков (вкл. 'all') → одна сводная таблица с дедупом.
    # Один список → подробная проверка этого файла, как раньше.
    if ($selected.Count -gt 1) {
        Check-CombinedLists $selected
    } else {
        foreach ($f in $selected) {
            $typeName = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
            # Капитализируем первую букву для красивого лога
            $typeName = $typeName.Substring(0,1).ToUpper() + $typeName.Substring(1)
            Check-List-WithLog $f.FullName $typeName
        }
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
    # v1.14.2: рамка считается программно (inner 59) — границы не «плывут»
    Write-Host ("  " + [char]0x250C + ("─ Certs\ ".PadRight(59, [char]0x2500)) + [char]0x2510) -ForegroundColor Cyan
    $i = 1
    foreach ($f in $files) {
        $active = if ($global:ActiveCerts -and $global:ActiveCerts.Contains($f.Name)) {
            " [ACTIVE]"
        } else { "" }
        $activeColor = if ($active) { "Cyan" } else { "White" }
        try {
            $c  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $f.FullName
            $cn = ($c.Subject -replace "CN=", "" -split ",")[0].Trim()
            # v1.14.2: строка дополняется до 59 символов и закрывается │ — рамка ровная
            $row = ("  {0,2}. {1,-28} {2,-22}{3}" -f $i, $f.Name, $cn, $active)
            if ($row.Length -gt 59) { $row = $row.Substring(0, 59) }
            Write-Host ("  │" + $row.PadRight(59) + "│") -ForegroundColor $activeColor
        } catch {
            $row = ("  {0,2}. {1,-30} (не удалось прочитать){2}" -f $i, $f.Name, $active)
            if ($row.Length -gt 59) { $row = $row.Substring(0, 59) }
            Write-Host ("  │" + $row.PadRight(59) + "│") -ForegroundColor DarkGray
        }
        $i++
    }
    Write-Host ("  " + [char]0x2514 + ([string][char]0x2500 * 59) + [char]0x2518) -ForegroundColor Cyan
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

# ── Авто-режим (Планировщик задач) ───────────────────────────────────
# Если передан -RunList <имя|all> — гоним проверку без меню, сохраняем
# логи в Logs\ и выходим. Сюда же попадает запуск из schtasks.
if ($RunList) {
    $global:CachedExternalIP = Get-ExternalIP
    $global:CachedGeo        = Get-Geo $global:CachedExternalIP
    Invoke-AutoRun -ListName $RunList
    exit
}

# ── Первичная инициализация — один раз, до цикла ─────────────────────
Write-Host "  Получаем сетевые данные..." -ForegroundColor DarkGray
$global:CachedExternalIP = Get-ExternalIP
$global:CachedGeo        = Get-Geo $global:CachedExternalIP
$global:CachedDns        = Get-DnsServers
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
        "3"  { Manage-Schedule }
        "4"  { Show-DnsCheck }
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
        # L/Л — включить/выключить легенду в правой колонке (RU и EN раскладка)
        "L"  { $global:ShowLegend = -not $global:ShowLegend }
        "Л"  { $global:ShowLegend = -not $global:ShowLegend }
        "0"  { exit }
    }

    } catch {
        # Ошибки цикла меню не показываем пользователю.
        # Для диагностики: запусти с -DebugMode или нажми 10.
        Write-Verbose "Menu loop error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        Start-Sleep -Milliseconds 300
    }
} while ($true)
