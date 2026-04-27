# NetworkChecker — Техническая документация

**Версия:** v1.14.1  
**Язык:** PowerShell 5.1  
**Среда:** Windows 10/11, .NET 4.x, права администратора  
**Авторы:** Anton Sidorenko (Lead Architect) & AI Team (Claude, Google AI, GPT-4, DeepSeek)

---

## Оглавление

1. [Назначение и архитектура](#1-назначение-и-архитектура)
2. [Структура файлов](#2-структура-файлов)
3. [Слой инициализации](#3-слой-инициализации)
4. [Диагностические функции](#4-диагностические-функции)
5. [Вспомогательные функции](#5-вспомогательные-функции)
6. [UI-функции](#6-ui-функции)
7. [Режимы проверки](#7-режимы-проверки)
8. [Система логирования](#8-система-логирования)
9. [Smart Arbitration](#9-smart-arbitration)
10. [Debug-режим](#10-debug-режим)
11. [Локализация](#11-локализация)
12. [Цветовая логика](#12-цветовая-логика)
13. [Известные ограничения и подводные камни](#13-известные-ограничения-и-подводные-камни)
14. [Как собрать с нуля](#14-как-собрать-с-нуля)

---

## 1. Назначение и архитектура

NetworkChecker — инструмент глубокой сетевой диагностики. Обычный `ping` или `curl` показывают только верхушку айсберга. NetworkChecker проверяет весь стек от DNS до HTTP.

**Диагностическая цепочка для каждого домена:**
```
DNS резолвинг → TCP connect → TLS handshake → Сертификат → HTTP запрос → Итоговый статус
```

Каждый шаг независим. Если DNS упал — дальше не идём. Если TLS упал — HTTP пропускаем. Если всё прошло — смотрим на сертификат и HTTP-код.

**Почему это важно в РФ:**
- Провайдеры блокируют на разных уровнях: DNS (NXDOMAIN), TCP (таймаут), TLS (RST при SNI), HTTP (подмена ответа)
- ICMP (ping) режется отдельно от TCP — `PING:timeout` не означает что сайт недоступен
- Некоторые провайдеры подменяют сертификаты (MITM) — без TLS-проверки это не видно
- Российские банки используют отечественные CA которых нет в Windows по умолчанию → ложный MITM

**Архитектура: монолит сознательно.**  
Один `.ps1` файл без зависимостей. `xcopy`-деплой: скопировал папку — работает. PowerShell модули добавляют сложность установки которая не нужна диагностическому инструменту.

---

## 2. Структура файлов

```
NetworkChecker\
  NetworkChecker_v1.14.ps1     ← единственный файл скрипта
  lists\                        ← папка со списками доменов
    russia.txt                  ← один домен на строку, # = комментарий
    foreign.txt
    streaming.txt
    custom.txt
    (любые .txt)                ← скрипт читает все .txt автоматически
  Logs\                         ← создаётся автоматически
    Log_Russia_2026-04-25_10-30.txt
    debug_verbose.log           ← пишется в Debug-режиме
  Certs\                        ← опционально
    russian_trusted_root_ca.cer ← для Smart Arbitration
    active_certs.txt            ← список активных (создаётся скриптом)
```

**Формат файла списка:**
```
# Это комментарий — строка игнорируется
google.com
vk.com
https://sberbank.ru/   ← Sanitize-Domain уберёт https:// и /
```

---

## 3. Слой инициализации

Выполняется один раз при запуске, до цикла меню. Порядок важен.

### 3.1 Права администратора

```powershell
if (-not IsInRole("Administrator")) {
    Start-Process powershell.exe "-ExecutionPolicy Bypass -File ..." -Verb RunAs
    exit
}
```

**Зачем:** `netstat -ano`, `Get-NetRoute`, `Get-NetIPAddress` требуют прав администратора. Без них функции возвращают пустые результаты без ошибок — молчаливое неправильное поведение хуже явной ошибки.

**Важно:** `try/catch` вокруг `Start-Process RunAs` — если UAC отклонён, пользователь видит понятное сообщение, а не красный стектрейс.

### 3.2 TLS для Invoke-WebRequest

```powershell
[Net.ServicePointManager]::SecurityProtocol = Tls12 -bor Tls13
```

**Зачем:** По умолчанию PS 5.1 использует устаревший TLS 1.0/1.1. Многие серверы его не принимают.

**Подводный камень:** `ServicePointManager` влияет ТОЛЬКО на `Invoke-WebRequest` и `Invoke-RestMethod`. На `SslStream` (который мы используем в `Get-CertInfo`) — не влияет вообще. Это частый источник путаницы.

**Fallback:** `Tls13` может отсутствовать в `.NET 4.x` на старых Windows 10. Оборачиваем в `try/catch`, при ошибке используем только `Tls12`.

### 3.3 C# класс TrustAllCerts

```powershell
Add-Type -TypeDefinition @"
public class TrustAllCerts {
    public static bool ReturnTrue(object sender, X509Certificate cert,
        X509Chain chain, SslPolicyErrors errors) { return true; }
}
"@
```

**Зачем:** При проверке сертификата нам нужно получить его данные даже если он невалидный (просроченный, MITM, самоподписанный). Стандартная валидация бросит исключение и мы ничего не увидим. `TrustAllCerts.ReturnTrue` говорит SslStream "принять любой сертификат" — а мы потом сами анализируем что пришло.

**Почему C#, а не ScriptBlock:**  
`SslStream.AuthenticateAsClientAsync` запускает TLS-рукопожатие в пуле потоков .NET. PS Runspace туда не передаётся. ScriptBlock при вызове из чужого потока бросает `"Нет пространства выполнения"` — TLS:FAIL на каждом домене.

### 3.4 TrustAllCallback через Delegate::CreateDelegate

```powershell
$global:TrustAllCallback = [System.Delegate]::CreateDelegate(
    [RemoteCertificateValidationCallback],
    [TrustAllCerts].GetMethod('ReturnTrue')
)
```

**Зачем:** В PS 5.1 прямой каст `[TrustAllCerts]::ReturnTrue` → делегат не работает (`ConvertToFinalInvalidCastException`). `Delegate::CreateDelegate` — единственный надёжный способ в `.NET 4.x / PS 5.1` связать статичный C# метод с нужным типом делегата.

### 3.5 Инициализация перед циклом меню

```powershell
Load-ActiveCerts                             # загружаем активные .cer
Write-Host "Получаем сетевые данные..."
$global:CachedExternalIP = Get-ExternalIP   # HTTP-запрос раз
$global:CachedGeo        = Get-Geo $ip      # HTTP-запрос два
Test-TimeDrift                               # проверка дрейфа часов
```

**Зачем кэш:** `Show-IPInfo` вызывается на каждой итерации цикла меню (после каждого действия). Если делать HTTP-запросы внутри неё — `Clear-Host` + 6 секунд ожидания = чёрный экран при каждом возврате в меню.

---

## 4. Диагностические функции

### 4.1 `Resolve-Domain`

**Назначение:** Получить IP-адрес домена.

**Логика:**
1. Первая попытка: `Resolve-DnsName` — нативный DNS клиент Windows, поддерживает DoH
2. Вторая попытка: `[System.Net.Dns]::GetHostAddresses` — .NET DNS fallback
3. Возвращает `@{ OK=$true; IP="1.2.3.4" }` или `@{ OK=$false; IP="" }`

**Зачем два метода:** `Resolve-DnsName` может упасть если DNS-модуль не загружен (редко, но бывает). `.NET Dns` всегда доступен.

**Подводный камень:** При первом вызове `Resolve-DnsName` PowerShell импортирует DNS-модуль с многочисленными `Write-Verbose "Экспорт функции..."`. Эти сообщения перехватываются нашим кастомным `Write-Verbose` и фильтруются по паттерну `'^(Экспорт|Импорт|...) '`.

### 4.2 `Get-CertInfo`

**Назначение:** Полная TLS/сертификатная диагностика домена.

**Параметры:** `$Domain` (строка), `$TimeoutMs` (по умолчанию 3000мс)

**Возвращает хэштейл:**
```powershell
@{
    Status   = "OK" | "FAIL"
    TLS      = "OK" | "FAIL"
    Expiry   = "2026-06-30"        # дата истечения
    DaysLeft = 40                   # дней до истечения
    Subject  = "CN=*.google.com"    # кому выдан
    Issuer   = "CN=GTS CA 1C3..."   # кем выдан
    Trust    = "TRUSTED" | "MITM" | "EXPIRED" | "SELF-SIGN" | "!CHAIN" | "DPI/RST" | "TRUSTED (File)" | "TRUSTED (CDN)"
    Reason   = "OK" | "DPI/RST" | "TCP timeout" | ...  # машиночитаемая причина
    Error    = "Exception message"  # полный текст ошибки для Verbose
    CdnCert  = $true | $false       # маркер CDN-сертификата
}
```

**Последовательность проверок внутри:**

**Шаг 1 — TCP connect с таймаутом:**
```powershell
$ar = $tcpClient.BeginConnect($Domain, 443, $null, $null)
$connected = $ar.AsyncWaitHandle.WaitOne($TimeoutMs)
```
`BeginConnect`/`EndConnect` — асинхронный паттерн .NET. `EndConnect` обязателен по контракту: освобождает `IAsyncResult` и пробрасывает реальное исключение если коннект завершился с ошибкой (без него мы бы никогда не узнали причину).

**Шаг 2 — SslStream + TLS рукопожатие:**
```powershell
$sslStream = New-Object SslStream($tcpClient.GetStream(), $false, $TrustAllCallback)
$handshakeTask = $sslStream.AuthenticateAsClientAsync($Domain, $null, Tls12|Tls13, $false)
$completed = $handshakeTask.Wait($TimeoutMs)
```
`.Wait()` может: вернуть `true` (OK), вернуть `false` (таймаут), бросить исключение (RST). Все три случая обрабатываются отдельно. Проверяем ещё и `IsFaulted` — task мог завершиться с ошибкой не бросив через `.Wait()`.

**Шаг 3 — DPI/RST детекция:**
```powershell
if ($ex -is [SocketException] -and $ex.SocketErrorCode -eq ConnectionReset) {
    $result.Reason = "DPI/RST"
}
```
RST-инъекция провайдера при SNI даёт `SocketErrorCode == ConnectionReset`. Это точнее чем анализ текста сообщения.

**Шаг 4 — MITM детекция:**
Проверяем совпадение CN сертификата с доменом по трём правилам (в порядке приоритета):
1. Точное совпадение: `CN == domain`
2. Wildcard: `CN = *.example.com` покрывает `sub.example.com`
3. SAN (Subject Alternative Names): все точные совпадения и wildcards из расширения

**Шаг 5 — CDN детекция:**
```powershell
# yandex.ru получает CN=*.yandex.tr — разный TLD, тот же владелец
$cnBase  = извлекаем 2LD из CN   # "yandex" из "*.yandex.tr"
$domBase = извлекаем 2LD домена  # "yandex" из "yandex.ru"
if ($cnBase -eq $domBase) → TRUSTED (CDN), $result.CdnCert = $true
```
Без этой проверки Яндекс, некоторые CDN и банки с геораспределёнными сертификатами получали бы MITM.

**Шаг 6 — Smart Arbitration:**  
Если ни одна проверка не совпала — передаём в `Test-CertArbitration`. Если там есть подходящий `.cer` — `TRUSTED (File)`. Иначе — `MITM`.

**Шаг 7 — X509Chain:**  
`chain.Build($cert)` проверяет цепочку доверия. Перебираем `chain.ChainStatus` для конкретной причины: `PartialChain`, `UntrustedRoot`, `Revoked`.

**finally блок — обязателен:**
```powershell
finally {
    try { $sslStream.Dispose() } catch {}
    try { $tcpClient.Close()   } catch {}
    try { $tcpClient.Dispose() } catch {}
}
```
При RST/DPI сокет может быть в состоянии `Faulted`. Стандартный `Dispose()` в этом случае бросает `ObjectDisposedException`. Каждый вызов в отдельном `try/catch`. Порядок важен: сначала верхний слой (SSL), потом нижний (TCP).

### 4.3 `Test-Domain`

**Назначение:** Оркестратор — собирает полную картину по домену.

**Вызывает:** `Resolve-Domain` → `Get-PingStats` → `Get-CertInfo` → `Invoke-WebRequest`

**Возвращает PSCustomObject** для таблицы:
```powershell
[PSCustomObject]@{
    Domain = "google.com"
    IP     = "142.250.74.46"
    DNS    = "OK"
    TLS    = "OK"
    HTTP   = "200"
    Ping   = "14 ms"
    Loss   = "0%"
    Cert   = "TRUSTED"
    Status = "UP"
}
```

**Status engine — логика итогового статуса:**

| Условие | Статус |
|---------|--------|
| DNS FAIL | DOWN |
| HTTP 2xx/3xx + CERT TRUSTED | UP |
| HTTP 2xx/3xx + CERT не TRUSTED | DEGRADED |
| TLS OK (HTTP заблокирован DPI) | DEGRADED |
| DNS OK + DPI/RST на SNI | DEGRADED |
| Всё остальное | DOWN |

**Ключевое решение:** Пинг не учитывается в статусе. В РФ ICMP режется провайдером независимо от доступности TCP. `PING:timeout` при `TLS:OK HTTP:200` = сайт работает, пинг режется.

**HTTP WAF bypass:**  
Полный набор заголовков Chrome в `$global:HttpHeaders`:
```
User-Agent: Mozilla/5.0 ... Chrome/122.0.0.0 ...
Accept: text/html,application/xhtml+xml,...
Accept-Language: ru-RU,ru;q=0.9,...
Connection: keep-alive
```
Без этих заголовков Cloudflare, VK и многие банки возвращают 403 — ложный FAIL.

**HTTP fallback:** HTTPS → HTTP. Если оба упали — `Get-HttpFailReason` анализирует исключение и возвращает `FAIL(403)`, `FAIL(RST)`, `FAIL(timeout)` и т.д.

### 4.4 `Get-PingStats`

**Назначение:** Статистика пинга с медианой.

**Параметры:** `$ip`, `$Count = 3`

**Возвращает:** `@{ Avg; Median; Min; Max; Loss }`

**Зачем медиана:** Среднее (`avg`) искажается одним долгим пакетом. Медиана показывает типичную задержку. Если `avg >> median` — был один выброс, а не общий лаг.

**Вычисление медианы:**
```powershell
$sorted = $times | Sort-Object
if ($sorted.Count % 2 -eq 0) {
    $median = ($sorted[$mid-1] + $sorted[$mid]) / 2  # чётное количество
} else {
    $median = $sorted[$mid]                           # нечётное
}
```

**Dispose в finally:** `System.Net.NetworkInformation.Ping` реализует `IDisposable`. При 100 доменах без `Dispose()` — 100 незакрытых объектов.

**Когда ICMP заблокирован:** Возвращает `@{ Avg="timeout"; Median="timeout"; Loss=100 }`. Строка "timeout" вместо числа — это намеренно. `Test-Domain` корректно обрабатывает этот случай (не падает, не влияет на статус).

### 4.5 `Get-ExternalIP`

**Назначение:** Получить внешний IP машины.

**Логика:** Два fallback-сервиса с таймаутом 3с:
1. `api.ipify.org` — быстрый, надёжный
2. `api.my-ip.io` — резервный

**Возвращает:** строку с IP или `"N/A"`

### 4.6 `Get-Geo`

**Назначение:** Геолокация по IP (страна, город, провайдер).

**Логика:** Три fallback-сервиса:
1. `ip-api.com/json/$ip` — возвращает `country, city (isp)`
2. `ipwho.is/$ip` — резервный с той же структурой
3. `ifconfig.me/all.json` — только `"Geo unavailable"` если первые два недоступны

**Почему третий fallback не показывает IP:** IP уже есть в строке `External IP:` шапки. Дублировать его в строке `Geo:` — избыточно и вводит в заблуждение.

### 4.7 `Get-GeoCode`

**Назначение:** Короткий 2-буквенный код страны для сетевого монитора (`RU`, `US`, `DE`).

**Кэш:** `$global:GeoCache` — хэштейл IP → код. Монитор обновляется каждые 3 секунды. Без кэша = 40+ API-запросов в минуту на каждое новое соединение.

**ЧастнΩые IP:** Возвращает `".."` для `10.x`, `192.168.x`, `172.16-31.x`, `127.x` — это LAN.

### 4.8 `Normalize-Error`

**Назначение:** Перевести текст .NET-исключения в человекочитаемый код.

**Логика:** `ToLower()` + серия `-match` паттернов по приоритету:
- `"forcibly closed"`, `"transport stream"`, `"connection was reset"` → `DPI/RST`
- `"timed out"`, `"handshake timeout"` → `Timeout`
- `"handshake"`, `"authentication"` → `TLS blocked`
- и т.д.

**Порядок важен:** `"forcibly closed"` должен идти до `"timed out"` — RST-ошибка может содержать оба паттерна.

### 4.9 `Get-HttpFailReason`

**Назначение:** Причина HTTP-ошибки из исключения `Invoke-WebRequest`.

**Возвращает:** `"403"`, `"401"`, `"timeout"`, `"RST"`, `"refused"`, `"TLS-err"`, `"DNS"`, `"FAIL"`

**Используется в:** `Test-Domain` и `Check-Single` — оба места делают одинаковый HTTP-запрос, причины одинаковые.

### 4.10 `Test-TimeDrift`

**Назначение:** Проверить синхронизацию системных часов.

**Зачем:** TLS-сертификаты имеют срок действия. Если системные часы отстают или спешат больше чем на 2 минуты — `chain.Build()` вернёт ошибку `NotTimeValid`. Все домены получат `CERT:FAIL` — полностью ложные результаты.

**Логика:** `worldtimeapi.org/api/ip` → сравниваем с `Get-Date().ToUniversalTime()`. Порог: 120 секунд. Запускается один раз при старте.

**Тихий fallback:** API недоступен → `Write-Verbose`, продолжаем без ошибки.

---

## 5. Вспомогательные функции

### 5.1 `Sanitize-Domain`

**Назначение:** Очистить пользовательский ввод до чистого доменного имени.

```
"https://google.com/search?q=test" → "google.com"
"  vk.com/  "                      → "vk.com"
"//t.me"                           → "t.me"
```

**Параметр:** `$raw` (не `$input`!)  
**Важно:** `$input` — зарезервированная переменная PowerShell (автоматический пайплайн-параметр). Использование как имени параметра ломает функцию при вызове через `ForEach-Object { Sanitize-Domain $_ }`.

**CRLF фикс:** `$raw -replace '\`r', ''` — файлы списков могут быть сохранены с Windows line endings (`\r\n`). Без очистки `\r` домен будет `"google.com\r"` — DNS FAIL.

### 5.2 `Write-Verbose` (override)

**Назначение:** Перехват системного Verbose для записи в Debug-лог.

```powershell
function Write-Verbose {
    param([string]$Message)
    if ($Message -match '^(Экспорт|Импорт|Загрузка|Loading|...) ') { return }
    if ($global:DebugLogPath) {
        "[HH:mm:ss] $Message" | Out-File $DebugLogPath -Append
    }
    if ($VerbosePreference -eq 'Continue') {
        Microsoft.PowerShell.Utility\Write-Verbose $Message
    }
}
```

**Зачем override:** PS 5.1 не поддерживает `Tee-Object` для Verbose-потока. Единственный способ перехватить `Write-Verbose` из любой функции — переопределить его в глобальной области.

**Фильтр шума:** При первом вызове `Resolve-DnsName` PS импортирует DNS-модуль и генерирует 15+ строк `"VERBOSE: Экспорт функции..."`. Без фильтра они засоряют Debug-окно.

**Вызов оригинала:** `Microsoft.PowerShell.Utility\Write-Verbose` — явное указание модуля обходит рекурсию.

### 5.3 `Write-TwoColumns`

**Назначение:** Вывести два массива текста бок о бок (левая и правая колонка).

**Параметры:** `$Left`, `$Right` (массивы pscustomobject `{T="text"; C="Color"}`), `$LeftW = 44`

**Anti-Flicker:** Формируем левую часть в памяти (`PadRight($LeftW)`), потом два `Write-Host` подряд. Это минимизирует мерцание. `SetCursorPosition` — убран: ломал позиционирование при любом изменении размера окна.

**Почему pscustomobject, а не `@("text","color")`:**  
В PS 5.1 `@("text","color")[0]` возвращает `"t"` (первый символ строки), а не `"text"`. Это не очевидно и ломалось очень неожиданно. `[pscustomobject]@{T="text";C="Color"}` — стабильно в любой версии.

**Fallback:** Если цвет невалидный (`$color -notmatch '^[A-Za-z]+$'`) → `"White"`. Защита от `$null` в полях.

### 5.4 `Get-TC` (внутренняя)

Хелпер внутри `Write-TwoColumns`. Читает `.T`/`.C` из pscustomobject и fallback на старый формат массива `@("text","color")` для обратной совместимости.

### 5.5 `Get-NetSpeed`

**Назначение:** Скорость сети по процессам для сетевого монитора.

**Текущая реализация:** Заглушка. Возвращает пустой хэш → монитор показывает `"-"` в колонке KB/s. Реальный трафик через `WMI/perf counters` слишком медленный для 3-секундного тика монитора.

**Потенциальный фикс:** `Get-Counter '\Process(*)\IO Data Bytes/sec'` — доступен на большинстве систем, но добавляет ~500мс задержки.

---

## 6. UI-функции

### 6.1 `Show-IPInfo`

**Назначение:** Отрисовать главный экран — шапку с IP/Geo и меню.

**Архитектура:** `Write-TwoColumns` с двумя колонками:
- Левая (LeftW=38): логотип + IP/Geo + пункты меню (16 строк)
- Правая: `$global:LegendData[$lang]` — легенда статусов

**Нет HTTP-запросов:** Только кэш (`$global:CachedExternalIP`, `$global:CachedGeo`). HTTP-запросы делаются один раз в инициализации перед циклом меню.

### 6.2 `$global:LegendData`

**Назначение:** Единый источник данных для легенды.

**Структура:** Хэш с ключами `"RU"` и `"EN"`, каждый = массив pscustomobject `{T; C}`.

**Используется в двух местах:**
1. `Show-IPInfo` — правая колонка главного меню
2. `Show-Legend` — overlay по кнопке L

Единый источник гарантирует что обе легенды показывают одинаковые данные.

### 6.3 `Show-Legend`

**Назначение:** Полная легенда по кнопке L.

**Логика:** Итерация по `$global:LegendData[$lang]`, каждая строка — `Write-Host` с цветом из `.C`. В конце — `Read-Host "Enter — меню"`.

**Вызов:** Из `switch` меню при `"L"` или `"Л"` (RU-раскладка). `.ToUpper()` в switch — работает в любом регистре.

### 6.4 `Show-Manual`

**Назначение:** Полное руководство пользователя (пункт 7).

**Структура (RU):**
- Что это и для чего
- Структура папок
- Запуск
- Пункты меню
- Как читать результаты (DNS/TLS/HTTP/PING/CERT/Статус)
- Smart Arbitration — обеление банков
- Логи и отчёты
- Авторство и история версий

**Две версии:** `if ($global:Lang -ne "EN")` — русская (подробная, 7 разделов), иначе английская (сжатая, 5 разделов). В конце обеих — `Read-Host "Enter — меню"`.

**Формат:** Простые `Write-Host` без `Write-TwoColumns`. Документ прокручивается мышью. Секции выделены `▌ ЗАГОЛОВОК` желтым с серой линией под ним.

### 6.5 `Show-SideHelp`

**Назначение:** Контекстные подсказки для режимов (ListScan, Single, Monitor, Certs).

**Статус:** Функция определена и содержит данные, но **не вызывается** — убрана из всех режимов в v1.14.1 как источник проблем с выравниванием. Данные сохранены на случай если понадобится вернуть.

### 6.6 `Show-NetMonitor`

**Назначение:** Сетевой монитор в реальном времени.

**Цикл:** `while($true)` с 3-секундным тиком. Выход по `Q` / `Й` через `[Console]::KeyAvailable` и `ReadKey($true)`.

**Источник данных:** `netstat -ano` — парсим вывод регулярками. Фильтруем: TCP ESTABLISHED/SYN/LISTEN + UDP :53.

**Таблица (78 символов):**
```
Process            State  Remote                 Geo  KB/s     PID
chrome             ESTAB  142.251.151.119:443    US   -        9808
```

**Цвета строк:**
- `ESTABLISHED` → зелёный
- `SYN_SENT`, `SYN_RECEIVED` → красный (ожидание/блокировка)
- `LISTENING` → голубой
- `UDP` (порт 53) → тёмно-жёлтый (DNS)

**Geo кэш:** `$global:GeoCache` — сбрасывается при входе в монитор, заполняется по мере появления новых IP.

---

## 7. Режимы проверки

### 7.1 `Invoke-MultiList` (пункт 2)

**Назначение:** Файловый браузер списков — читает все `.txt` из `lists\`, без хардкода имён.

**UX:** Показывает нумерованный список с количеством доменов в каждом файле. Ввод: `1`, `1,3`, `all`, `0` (отмена).

**Зачем нет хардкода:** Пользователь может создать любые списки: `company.txt`, `banks.txt`, `my-domains.txt` — скрипт найдёт их автоматически.

**Капитализация:** `$typeName.Substring(0,1).ToUpper() + ...` — имя файла без расширения как тип в логе: `russia.txt` → `Russia` → `Log_Russia_...txt`.

### 7.2 `Check-List-WithLog`

**Назначение:** Проверить список доменов из файла, вывести таблицу, предложить сохранить лог.

**Прогресс-бар:**
```
[████████████░░░░░░░░] 60%  google.com
```
`\r` перед баром — возврат каретки без новой строки. После `Test-Domain` — `\r` снова и уже результат на чистую строку. `{0,-40}` фиксированная ширина поля домена — без этого хвосты длинных доменов остаются на экране.

**Summary строка:**
```
Итог: Всего=37  UP=24  DEGRADED=12  DOWN=1  Avg Ping=33ms
```
Regex `' UP '`, `' DEGRADED '`, `' DOWN '` — пробелы вокруг гарантируют что мы считаем статус, а не часть доменного имени.

**Avg Ping в Summary:** Парсим PING-колонку из уже напечатанных строк: `if ($_ -match 'PING:(\d+)')`. Только числа — timeout не учитывается.

**Цвет строки:**
- `UP` → зелёный
- `DEGRADED` → жёлтый
- `DOWN` → красный
- `TRUSTED (File)` → голубой (Cyan)
- `TRUSTED (CDN)` → тёмно-голубой (DarkCyan)

### 7.3 `Check-Single` (пункт 6)

**Назначение:** Глубокая диагностика одного или нескольких доменов с подробным выводом.

**Отличия от Check-List:**
- Вертикальный формат (каждое поле на отдельной строке)
- Полная информация о сертификате: дата, количество дней, Trust, Subject
- Медиана пинга выделена цветом (зелёный < 50мс, жёлтый < 150мс, красный > 150мс)
- Подсказка `[avg≠median: выброс пинга]` если расхождение > 10мс
- MITM предупреждение с пояснением про антивирусы

**Лог Single:** Вертикальный формат с временными метками на каждый домен. Шапка с External IP и Geo. Сохраняется в `Logs\Log_Single_...txt`.

---

## 8. Система логирования

### 8.1 `Save-Log`

**Параметры:** `$Type`, `$Content`, `$ExternalIP`, `$Geo`

**Формат файла:**
```
Log_Russia_2026-04-25_10-30.txt
Log_Foreign_2026-04-25_11-15.txt
Log_Single_2026-04-25_12-00.txt
debug_verbose.log
```

**Шапка лога:**
```
NetworkChecker v1.14 — Лог проверки
=====================================
Дата       : 2026-04-25
Время      : 10:30:15
Тип        : Russia
External IP: 94.228.112.104
Geo        : Russia, Saint Petersburg (JSC TIMEWEB)
=====================================
[содержимое]
```

**Кодировка:** UTF-8 (`Out-File -Encoding UTF8`). Важно для кириллицы и Unicode-символов в именах доменов.

---

## 9. Smart Arbitration

### 9.1 Проблема

Российские банки (Сбербанк, Газпромбанк и др.) и госсайты используют сертификаты от НУЦ Минцифры. Этот CA не входит в стандартное хранилище Windows. `X509Chain.Build()` возвращает `false` → скрипт показывает `MITM` — это ложная тревога.

### 9.2 `Test-CertArbitration`

**Логика:**
1. Берём список активных `.cer` файлов из `Certs\` (фильтруем по `$global:ActiveCerts`)
2. Для каждого файла: читаем сертификат через `X509Certificate2`
3. Проверяем совпадение Subject: `$c.Subject -eq $CertSubject`
4. Проверяем SAN: `$san.Format($false) -match [regex]::Escape($Domain)`
5. Если совпало → возвращаем `"TRUSTED (File)"`

**Интеграция в Get-CertInfo:**  
Вызывается ПОСЛЕ всех стандартных проверок, если `$certMatch` остался `$false`. Это последний шанс перед вынесением вердикта MITM.

### 9.3 `Load-ActiveCerts` / `Save-ActiveCerts`

**Персистентность:** `Certs\active_certs.txt` — список имён активных `.cer` файлов, по одному на строку. Загружается при старте, обновляется после каждого изменения в пункте 9.

**OrdinalIgnoreCase:** `New-Object 'HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)` — Windows ФС регистронезависима: `"RootCA.cer"` и `"rootca.cer"` — один файл. HashSet по умолчанию — нет, нужен явный компаратор.

### 9.4 `Select-CertFile` (пункт 9)

**UX:** Показывает нумерованный список `.cer` с CN и маркером `[ACTIVE]`. Toggle по номеру: если уже активен — деактивируем, если нет — активируем. `all` / `0` для массовых операций.

---

## 10. Debug-режим

### 10.1 `Start-DebugWindow`

**Назначение:** Открыть отдельное окно PowerShell с живым Verbose-логом.

**Механизм:**
1. Создаём `Logs\debug_verbose.log` с заголовком сессии
2. `Start-Process powershell.exe` с командой `Get-Content -Path ... -Wait` — аналог `tail -f`
3. Записываем PID процесса в `$global:DebugWindowJob`
4. Устанавливаем `VerbosePreference = 'Continue'`

**Содержимое лога:** Все `Write-Verbose` вызовы с временными метками `[HH:mm:ss]`:
```
[10:30:15] [google.com] TCP connect...
[10:30:15] [google.com] TCP OK, starting TLS...
[10:30:15] [google.com] TLS handshake OK
[10:30:15] [google.com] Cert: CN=*.google.com expires 2026-06-30
```

### 10.2 `Stop-DebugWindow`

Убивает процесс Debug-окна через сохранённый PID. Сбрасывает `VerbosePreference = 'SilentlyContinue'`.

### 10.3 Запуск с `-DebugMode`

```powershell
powershell -ExecutionPolicy Bypass -File NetworkChecker_v1.14.ps1 -DebugMode
```
Активирует `VerbosePreference = 'Continue'` до открытия меню — весь вывод включая инициализацию.

---

## 11. Локализация

**Механизм:** `$global:T` — хэш с ключами `"RU"` и `"EN"`, каждый = хэш строк.

```powershell
$global:T = @{
    RU = @{ Choice = "Выбор"; Summary = "Итог"; ... }
    EN = @{ Choice = "Choice"; Summary = "Summary"; ... }
}
function T { param([string]$k); $global:T[$global:Lang][$k] }
```

**Переключение:** Пункт 8 — `$global:Lang = if ($Lang -eq "RU") { "EN" } else { "RU" }`. Мгновенно, без перезапуска. При следующей итерации цикла `Show-IPInfo` перерисует меню на новом языке.

**Легенда:** `$global:LegendData` содержит `"RU"` и `"EN"` — обновляется автоматически через `$lang = if ($isRU) { "RU" } else { "EN" }`.

**Не локализовано (намеренно или нет):**
- `Check-Single` — сообщения "Пингую N раз...", "Статус: DOWN (DNS не прошёл)" — русские строки
- `Save-Log` — шапка лога всегда на русском
- `Select-CertFile` — диалоги на русском

---

## 12. Цветовая логика

| Значение | Цвет | PowerShell |
|----------|------|-----------|
| UP | Зелёный | `Green` |
| DEGRADED | Жёлтый | `Yellow` |
| DOWN | Красный | `Red` |
| TRUSTED | Белый (нейтральный) | `White` |
| TRUSTED (CDN) | Тёмно-голубой | `DarkCyan` |
| TRUSTED (File) | Голубой | `Cyan` |
| MITM | Красный | `Red` |
| DPI/RST | Красный | `Red` |
| EXPIRED / !CHAIN | Серый | `DarkGray` |
| Прогресс-бар | Серый | `DarkGray` |
| Заголовки/рамки | Голубой | `Cyan` |
| Шапка версии | Жёлтый | `Yellow` |
| Подсказки/комментарии | Серый | `DarkGray` |
| ESTAB (монитор) | Зелёный | `Green` |
| SYN-S/R (монитор) | Красный | `Red` |
| LISTEN (монитор) | Голубой | `Cyan` |
| UDP53 (монитор) | Тёмно-жёлтый | `DarkYellow` |

**Принцип:** Зелёный = хорошо, жёлтый = внимание (работает с оговоркой), красный = проблема, голубой = информационный/арбитраж, серый = метаданные.

---

## 13. Известные ограничения и подводные камни

### Нельзя трогать без последствий

| Что | Что сломается |
|-----|---------------|
| `TrustAllCallback` — ScriptBlock вместо C# делегата | TLS:FAIL на каждом домене ("нет пространства выполнения") |
| `EndConnect()` убрать | Утечка IAsyncResult, реальные ошибки соединения не видны |
| `finally` в `Get-CertInfo` убрать | Утечка TcpClient/SslStream при 100+ доменах, OOM |
| `Tls12\|Tls13` → хардкод `Tls12` | Серверы только на TLS 1.3 → ложный DPI/RST |
| CDN-детекцию убрать | yandex.ru, mail.ru → MITM |
| Порядок: CDN check → SAN check → MITM | CDN домены получат MITM |
| `OrdinalIgnoreCase` убрать | `RootCA.cer` ≠ `rootca.cer` в HashSet, арбитраж не найдёт |
| IP/Geo в цикле меню | Чёрный экран 6 секунд при каждом возврате в меню |
| `$input` как имя параметра | Функция сломается в пайплайне |
| `$global:T` = `@{}` — убрать ключ | `T('Choice')` → `$null` → `Read-Host $null` → ошибка |

### Ограничения PowerShell 5.1

- Нет `ForEach-Object -Parallel` → нет нативного параллелизма
- `::new()` с аргументами работает плохо → `New-Object` для конструкторов с параметрами
- ScriptBlock не пересекает границы потоков .NET
- Нет `?.` null-conditional оператора → везде явные проверки `-and`
- `[array][0]` на строке даёт символ, не элемент → только pscustomobject

### Зависимости от сети

- `Get-GeoCode` в мониторе: новые IP → запрос к `ip-api.com`. При плохой сети монитор замедлится
- `Test-TimeDrift`: `worldtimeapi.org` — если недоступен, проверка тихо пропускается
- Geo API rate limits: `ip-api.com` — 45 запросов/минуту без ключа

---

## 14. Как собрать с нуля

Минимальный скелет для воспроизведения логики:

**1. Права + TLS + C# делегат** (инициализация, строки 82-193)

**2. Базовые диагностические функции** в порядке зависимостей:
```
Normalize-Error → Sanitize-Domain → Resolve-Domain →
Get-PingStats → Get-CertInfo → Get-HttpFailReason → Test-Domain
```

**3. Сетевые утилиты:**
```
Get-LocalIP → Get-ExternalIP → Get-Geo → Get-GeoCode
```

**4. Smart Arbitration** (можно добавить позже):
```
Test-CertArbitration → Load-ActiveCerts → Save-ActiveCerts → Select-CertFile
```

**5. Логирование:** `Save-Log`

**6. Режимы проверки:**
```
Check-List-WithLog → Check-Single → Invoke-MultiList
```

**7. UI:**
```
$global:T + T() → $global:LegendData → Write-TwoColumns →
Show-IPInfo → Show-Legend → Show-Manual → Show-NetMonitor
```

**8. Debug:** `Start-DebugWindow → Stop-DebugWindow`

**9. Главный цикл:**
```powershell
Load-ActiveCerts
$global:CachedExternalIP = Get-ExternalIP
$global:CachedGeo        = Get-Geo $global:CachedExternalIP
do {
    Clear-Host; Show-IPInfo
    $c = Read-Host
    switch ($c.ToUpper()) { ... }
} while ($true)
```

**Минимальный тест первой сборки:**
```powershell
# Проверить один домен без UI:
$result = Test-Domain "google.com"
$result | Format-List
```

Если `Status = "UP"` и `Cert = "TRUSTED"` — ядро работает корректно.

---

*Документ описывает NetworkChecker v1.14.1. Все технические решения задокументированы в комментариях к коду. Для воспроизведения читай комментарии вместе с этим документом — они дополняют друг друга.*
