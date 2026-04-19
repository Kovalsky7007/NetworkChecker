if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Запуск от имени администратора для полной диагностики..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs

}
# ==============================
# 📁 Рабочая директория
# ==============================
Set-Location -Path $PSScriptRoot   # чтобы lists\ всегда были рядом со скриптом

# ==============================
# 🔤 UTF-8 вывод
# ==============================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8


# ==============================
# 🌐 ВНЕШНИЙ IP
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
# 🌍 GEO по IP
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
# 🖥 ЛОКАЛЬНЫЙ IP
# ==============================
function Get-LocalIP {
    try {
        Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown"
        } |
        Select-Object -First 1 -ExpandProperty IPAddress
    }
    catch {
        "N/A"
    }
}


# ==============================
# 📡 ПИНГ С СТАТИСТИКОЙ
# ==============================
function Get-PingStats {
    param($ip)

    if (-not $ip) {
        return @{ Avg="N/A"; Loss=100 }
    }

    try {
        $results = Test-Connection -ComputerName $ip -Count 3 -ErrorAction Stop

        $avg = ($results | Measure-Object ResponseTime -Average).Average
        return @{
            Avg = [math]::Round($avg,1)
            Loss = 0
        }
    }
    catch {
        return @{
            Avg = "timeout"
            Loss = 100
        }
    }
}


# ==============================
# 🔎 TLS CHECK (443 handshake)
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
# 🔎 ДОМЕН ТЕСТ
# ==============================
function Test-Domain {
    param($domain)

    $dns = "FAIL"
    $ip = ""
    $http = "FAIL"

    # DNS
    try {
        $res = Resolve-DnsName $domain -ErrorAction Stop |
               Where-Object { $_.Type -eq "A" } |
               Select-Object -First 1

        if ($res) {
            $dns = "OK"
            $ip = $res.IPAddress
        }
    }
    catch {}

    # ping + tls
    $pingAvg = "N/A"
    $loss = 100
    $tls = "FAIL"

    if ($ip) {
        $p = Get-PingStats $ip
        $pingAvg = $p.Avg
        $loss = $p.Loss

        $tls = Test-TLS $ip
    }

    # HTTP check (более честный)
    try {
        $r = Invoke-WebRequest "https://$domain" -Method Head -TimeoutSec 3 -UseBasicParsing -MaximumRedirection 3
        $http = $r.StatusCode
    }
    catch {
        try {
            $r = Invoke-WebRequest "http://$domain" -Method Head -TimeoutSec 3 -UseBasicParsing
            $http = $r.StatusCode
        }
        catch {
            $http = "FAIL"
        }
    }

    # ==============================
    # 🧠 STATUS ENGINE (улучшенный)
    # ==============================
    $status = "DOWN"

    if ($dns -eq "FAIL") {
        $status = "DOWN"
    }
    elseif ($dns -eq "OK" -and $tls -eq "FAIL") {
        $status = "DEGRADED"
    }
    elseif ($http -eq "FAIL") {
        $status = "DEGRADED"
    }
    elseif ($http -match "20|30") {
        $status = "UP"
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
# 📊 IP INFO
# ==============================
function Show-IPInfo {

    $local = Get-LocalIP
    $external = Get-ExternalIP
    $geo = Get-Geo $external

    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "IP информация" -ForegroundColor Yellow
    Write-Host "-------------------------------------"
    Write-Host "Local IP   : $local"
    Write-Host "External IP: $external"
    Write-Host "Geo        : $geo"
    Write-Host "=====================================" -ForegroundColor Cyan
}


# ==============================
# 🔌 CONNECTIONS
# ==============================
function Show-Connections {

    Write-Host "`n=== Активные соединения ===" -ForegroundColor Yellow

    $proc = @{}
    Get-Process | ForEach-Object {
        $proc[$_.Id] = $_.ProcessName
    }

    netstat -ano | ForEach-Object {

        if ($_ -notmatch "ESTABLISHED") { return }

        $line = ($_ -replace '\s+', ' ').Trim()
        $p = $line.Split(' ')

        if ($p.Count -lt 5) { return }

        $remote = $p[2]
        $pidRaw = $p[-1]

        if ($pidRaw -notmatch '^\d+$') { return }

        $pidValue = [int]$pidRaw

        $name = if ($proc.ContainsKey($pidValue)) { $proc[$pidValue] } else { "Unknown" }

        [PSCustomObject]@{
            Process = $name
            Remote  = $remote
            PID     = $pidValue
        }

    } | Sort-Object Process | Format-Table -AutoSize
}


# ==============================
# 📋 LIST CHECK
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

        Write-Host ("{0,-25} {1,-8} DNS:{2,-4} TLS:{3,-4} HTTP:{4,-6} PING:{5,-10} LOSS:{6,-6} IP:{7}" -f `
            $r.Domain,
            $r.Status,
            $r.DNS,
            $r.TLS,
            $r.HTTP,
            $r.Ping,
            $r.Loss,
            $r.IP
        )
    }
}


# ==============================
# 📟 MENU
# ==============================
do {
    Clear-Host

    Show-IPInfo

    Write-Host "`n1 - Соединения"
    Write-Host "2 - Russia"
    Write-Host "3 - Foreign"
    Write-Host "4 - Streaming"
    Write-Host "5 - Custom"
    Write-Host "0 - Выход"

    $c = Read-Host "Выбор"

    switch ($c) {
        "1" { Show-Connections; Read-Host "Enter" }
        "2" { Check-List "lists\russia.txt"; Read-Host "Enter" }
        "3" { Check-List "lists\foreign.txt"; Read-Host "Enter" }
        "4" { Check-List "lists\streaming.txt"; Read-Host "Enter" }
        "5" { Check-List "lists\custom.txt"; Read-Host "Enter" }
        "0" { exit }
    }

} while ($true)