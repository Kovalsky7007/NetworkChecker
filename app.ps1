if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Запуск от имени администратора для полной диагностики..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs
}

# ==============================
# РАБОЧАЯ ДИРЕКТОРИЯ
# ==============================
Set-Location -Path $PSScriptRoot   # чтобы lists\ всегда были рядом со скриптом

# ==============================
# UTF-8 ВЫВОД
# ==============================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8


# ==============================
# ВНЕШНИЙ IP
# ==============================
function Get-ExternalIP {
    try {
        (Invoke-RestMethod "https://api.ipify.org?format=text" -TimeoutSec 3).Trim()
    }
    catch {
        "N/A"
    }
}


# ==============================
# GEO ПО IP
# ==============================
function Get-Geo {
    param($ip)

    if (-not $ip -or $ip -eq "N/A") {
        return "No IP"
    }

    try {
        $r = Invoke-RestMethod "http://ip-api.com/json/$ip?fields=status,country,city,isp" -UserAgent "Mozilla/5.0"

        if ($r.status -ne "success") {
            return "Geo failed"
        }

        return "$($r.country), $($r.city) ($($r.isp))"
    }
    catch {
        return "Geo error"
    }
}


# ==============================
# ЛОКАЛЬНЫЙ IP (активный адаптер с Default Gateway)
# ИСПРАВЛЕНО: раньше хватал первый попавшийся адрес
# (мог быть виртуальный адаптер или статика без шлюза)
# ==============================
function Get-LocalIP {
    try {
        # Находим интерфейсы у которых есть Default Gateway — это и есть активные
        $activeIndex = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
                       Sort-Object RouteMetric |
                       Select-Object -First 1 -ExpandProperty InterfaceIndex

        Get-NetIPAddress -InterfaceIndex $activeIndex -AddressFamily IPv4 -ErrorAction Stop |
            Select-Object -First 1 -ExpandProperty IPAddress
    }
    catch {
        # Fallback: старый метод если Get-NetRoute недоступен
        try {
            Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
            Select-Object -First 1 -ExpandProperty IPAddress
        }
        catch {
            "N/A"
        }
    }
}


# ==============================
# ПИНГ С СТАТИСТИКОЙ
# ИСПРАВЛЕНО: PS 5.1 использует .ResponseTime, PS 7+ использует .Latency
# Решение: используем .NET System.Net.NetworkInformation.Ping напрямую —
# работает одинаково в обеих версиях
# ==============================
function Get-PingStats {
    param(
        $ip,
        [int]$Count = 3   # количество пингов (можно передать 5 или 10 для медианы)
    )

    if (-not $ip) {
        return @{ Avg="N/A"; Median="N/A"; Min="N/A"; Max="N/A"; Loss=100 }
    }

    try {
        $pingSender = New-Object System.Net.NetworkInformation.Ping
        $times = [System.Collections.Generic.List[int]]::new()
        $failed = 0

        for ($i = 0; $i -lt $Count; $i++) {
            $reply = $pingSender.Send($ip, 1000)   # таймаут 1 сек на каждый пинг

            if ($reply.Status -eq "Success") {
                $times.Add([int]$reply.RoundtripTime)
            }
            else {
                $failed++
            }
        }

        if ($times.Count -eq 0) {
            return @{ Avg="timeout"; Median="timeout"; Min="N/A"; Max="N/A"; Loss=100 }
        }

        # Считаем медиану
        $sorted = $times | Sort-Object
        $mid = [math]::Floor($sorted.Count / 2)
        if ($sorted.Count % 2 -eq 0) {
            $median = [math]::Round(($sorted[$mid - 1] + $sorted[$mid]) / 2, 1)
        }
        else {
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
}


# ==============================
# TLS CHECK (TCP:443 handshake)
# ==============================
function Test-TLS {
    param($ip)

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($ip, 443, $null, $null)

        if ($ar.AsyncWaitHandle.WaitOne(1200) -and $client.Connected) {
            $client.Close()
            return "OK"
        }

        $client.Close()
        return "FAIL"
    }
    catch {
        return "FAIL"
    }
}


# ==============================
# DNS RESOLVE
# ИСПРАВЛЕНО: добавлен fallback через [System.Net.Dns] на случай
# если Resolve-DnsName недоступен (некоторые минимальные сборки Windows)
# ==============================
function Resolve-Domain {
    param($domain)

    # Попытка 1: Resolve-DnsName (есть на большинстве систем)
    try {
        $res = Resolve-DnsName $domain -ErrorAction Stop |
               Where-Object { $_.Type -eq "A" } |
               Select-Object -First 1

        if ($res) {
            return @{ OK=$true; IP=$res.IPAddress }
        }
    }
    catch {}

    # Попытка 2: .NET fallback (работает везде)
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($domain) |
                     Where-Object { $_.AddressFamily -eq "InterNetwork" }

        if ($addresses) {
            return @{ OK=$true; IP=$addresses[0].ToString() }
        }
    }
    catch {}

    return @{ OK=$false; IP="" }
}


# ==============================
# ДОМЕН ТЕСТ (основная функция)
# ==============================
function Test-Domain {
    param(
        $domain,
        [int]$PingCount = 3   # по умолчанию 3 пинга, можно передать больше
    )

    $dns = "FAIL"
    $ip  = ""

    # DNS resolve (с fallback)
    $dnsResult = Resolve-Domain $domain
    if ($dnsResult.OK) {
        $dns = "OK"
        $ip  = $dnsResult.IP
    }

    # Пинг + TLS
    $pingAvg = "N/A"
    $loss    = 100
    $tls     = "FAIL"

    if ($ip) {
        $p       = Get-PingStats $ip -Count $PingCount
        $pingAvg = $p.Avg
        $loss    = $p.Loss
        $tls     = Test-TLS $ip
    }

    # HTTP check
    # ИСПРАВЛЕНО: добавлен User-Agent — без него VK, Ozon и другие сайты
    # возвращают 403/блокируют запрос, что давало ложный FAIL
    $http = "FAIL"
    $ua   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"

    try {
        $r = Invoke-WebRequest "https://$domain" -Method Head -TimeoutSec 4 `
             -UseBasicParsing -MaximumRedirection 3 -UserAgent $ua
        $http = $r.StatusCode
    }
    catch {
        # Если HTTPS упал — пробуем HTTP
        try {
            $r = Invoke-WebRequest "http://$domain" -Method Head -TimeoutSec 4 `
                 -UseBasicParsing -UserAgent $ua
            $http = $r.StatusCode
        }
        catch {
            $http = "FAIL"
        }
    }

    # ==============================
    # STATUS ENGINE
    # UP       — DNS OK + HTTP 2xx/3xx
    # DEGRADED — DNS OK + сервер виден (TLS или частичный HTTP), но полный доступ блокируется
    # DOWN     — DNS FAIL или всё недоступно
    # ==============================
    $status = "DOWN"

    if ($dns -eq "FAIL") {
        $status = "DOWN"
    }
    elseif ($http -match "^(2|3)") {
        # HTTP вернул успешный код — сайт работает
        $status = "UP"
    }
    elseif ($dns -eq "OK" -and ($tls -eq "OK" -or $loss -lt 100)) {
        # DNS прошёл, сервер пингуется или TCP открыт — но HTTP заблокирован
        # Классический признак DPI/замедления
        $status = "DEGRADED"
    }

    return [PSCustomObject]@{
        Domain = $domain
        IP     = $ip
        DNS    = $dns
        TLS    = $tls
        HTTP   = $http
        Ping   = "$pingAvg ms"
        Loss   = "$loss %"
        Status = $status
    }
}


# ==============================
# IP INFO
# ==============================
function Show-IPInfo {
    $local    = Get-LocalIP
    $external = Get-ExternalIP
    $geo      = Get-Geo $external

    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "IP информация" -ForegroundColor Yellow
    Write-Host "-------------------------------------"
    Write-Host "Local IP   : $local"
    Write-Host "External IP: $external"
    Write-Host "Geo        : $geo"
    Write-Host "=====================================" -ForegroundColor Cyan
}


# ==============================
# CONNECTIONS
# ==============================
function Show-Connections {
    Write-Host "`n=== Активные соединения ===" -ForegroundColor Yellow

    $proc = @{}
    Get-Process | ForEach-Object { $proc[$_.Id] = $_.ProcessName }

    netstat -ano | ForEach-Object {
        if ($_ -notmatch "ESTABLISHED") { return }

        $line = ($_ -replace '\s+', ' ').Trim()
        $p    = $line.Split(' ')

        if ($p.Count -lt 5) { return }

        $remote   = $p[2]
        $pidRaw   = $p[-1]

        if ($pidRaw -notmatch '^\d+$') { return }

        $pidValue = [int]$pidRaw
        $name     = if ($proc.ContainsKey($pidValue)) { $proc[$pidValue] } else { "Unknown" }

        [PSCustomObject]@{
            Process = $name
            Remote  = $remote
            PID     = $pidValue
        }

    } | Sort-Object Process | Format-Table -AutoSize
}


# ==============================
# LIST CHECK
# ==============================
function Check-List {
    param($file)

    if (-not (Test-Path $file)) {
        Write-Host "Файл $file не найден" -ForegroundColor Red
        return
    }

    Write-Host "`n=== Проверка: $file ===" -ForegroundColor Cyan

    $domains = Get-Content $file | Where-Object { $_ -and -not $_.StartsWith("#") }

    foreach ($d in $domains) {
        $r = Test-Domain $d

        $color = switch ($r.Status) {
            "UP"       { "Green" }
            "DEGRADED" { "Yellow" }
            "DOWN"     { "Red" }
            default    { "White" }
        }

        Write-Host ("{0,-25} {1,-8} DNS:{2,-4} TLS:{3,-4} HTTP:{4,-6} PING:{5,-10} LOSS:{6,-6} IP:{7}" -f `
            $r.Domain, $r.Status, $r.DNS, $r.TLS, $r.HTTP, $r.Ping, $r.Loss, $r.IP
        ) -ForegroundColor $color
    }
}


# ==============================
# ОДИНОЧНАЯ ПРОВЕРКА С МЕДИАНОЙ (пункт 6)
# Позволяет ввести домен(ы) вручную и получить детальную статистику
# ==============================
function Check-Single {

    Write-Host "`n=== Одиночная проверка ===" -ForegroundColor Cyan
    Write-Host "Введите домен(ы) через запятую (например: google.com,vk.com)"

    $input = Read-Host "Домен(ы)"
    if (-not $input) { return }

    # Количество пингов
    Write-Host "Количество пингов для медианы [по умолчанию 10]:"
    $countRaw = Read-Host "Количество (Enter = 10)"

    # ИСПРАВЛЕНО: не используем тернарный оператор ?: — он не работает в PS 5.1
    if ($countRaw -match '^\d+$' -and [int]$countRaw -gt 0) {
        $pingCount = [int]$countRaw
    }
    else {
        $pingCount = 10
    }

    $domains = $input -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($domain in $domains) {
        Write-Host "`n--- $domain ---" -ForegroundColor Cyan

        # DNS
        $dnsResult = Resolve-Domain $domain
        $dns = if ($dnsResult.OK) { "OK" } else { "FAIL" }
        $ip  = $dnsResult.IP

        Write-Host "DNS    : $dns  IP: $ip"

        if (-not $ip) {
            Write-Host "Статус : DOWN (DNS не прошёл)" -ForegroundColor Red
            continue
        }

        # Пинг с медианой
        Write-Host "Пингую $pingCount раз..." -NoNewline
        $p = Get-PingStats $ip -Count $pingCount
        Write-Host " готово"

        Write-Host ("Ping   : avg={0}ms  median={1}ms  min={2}ms  max={3}ms  loss={4}%" -f `
            $p.Avg, $p.Median, $p.Min, $p.Max, $p.Loss)

        # TLS
        $tls = Test-TLS $ip
        Write-Host "TLS    : $tls"

        # HTTP
        $ua  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
        $http = "FAIL"
        try {
            $r = Invoke-WebRequest "https://$domain" -Method Head -TimeoutSec 4 `
                 -UseBasicParsing -MaximumRedirection 3 -UserAgent $ua
            $http = $r.StatusCode
        }
        catch {
            try {
                $r = Invoke-WebRequest "http://$domain" -Method Head -TimeoutSec 4 `
                     -UseBasicParsing -UserAgent $ua
                $http = $r.StatusCode
            }
            catch { $http = "FAIL" }
        }
        Write-Host "HTTP   : $http"

        # Итоговый статус
        $status = "DOWN"
        if ($http -match "^(2|3)") {
            $status = "UP"
        }
        elseif ($dns -eq "OK" -and ($tls -eq "OK" -or $p.Loss -lt 100)) {
            $status = "DEGRADED"
        }

        $color = switch ($status) {
            "UP"       { "Green" }
            "DEGRADED" { "Yellow" }
            "DOWN"     { "Red" }
            default    { "White" }
        }

        Write-Host "Статус : $status" -ForegroundColor $color
    }
}


# ==============================
# МЕНЮ
# ==============================
do {
    Clear-Host

    Show-IPInfo

    Write-Host "`n1 - Соединения"
    Write-Host "2 - Russia"
    Write-Host "3 - Foreign"
    Write-Host "4 - Streaming"
    Write-Host "5 - Custom"
    Write-Host "6 - Одиночная проверка (медиана пинга)"
    Write-Host "0 - Выход"

    $c = Read-Host "Выбор"

    switch ($c) {
        "1" { Show-Connections; Read-Host "Enter" }
        "2" { Check-List "lists\russia.txt"; Read-Host "Enter" }
        "3" { Check-List "lists\foreign.txt"; Read-Host "Enter" }
        "4" { Check-List "lists\streaming.txt"; Read-Host "Enter" }
        "5" { Check-List "lists\custom.txt"; Read-Host "Enter" }
        "6" { Check-Single; Read-Host "Enter" }
        "0" { exit }
    }

} while ($true)