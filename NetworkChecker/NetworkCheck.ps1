# =============================================
#   Network & VPN Checker v3.2 — Финальная версия
# =============================================

Set-Location -Path $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "Проверка сети • v3.2"

function Write-Color {
    param([string]$Text, [string]$Color = "White", [switch]$NoNewline)
    Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
}

# 1. Определяем локальный IP (строго IPv4 активного адаптера)
$localIP = try { 
    (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1 | Get-NetIPAddress -AddressFamily IPv4).IPAddress 
} catch { "Не определён" }

# 2. Определяем внешний IP (используем сервис, который не шлет HTML)
$externalIP = try { 
    (Invoke-RestMethod -Uri "https://ipify.org" -TimeoutSec 2 -ErrorAction Stop).Trim()
} catch { 
    try { (Invoke-RestMethod -Uri "https://icanhazip.com" -TimeoutSec 2).Trim() }
    catch { "Не удалось определить" }
}

do {
    Clear-Host
    Write-Color "=============================================" "Cyan"
    Write-Color "     Проверка сети, VPN и сервисов v3.2" "Cyan"
    Write-Color "=============================================`n" "Cyan"

    Write-Color "Локальный IP : " "White" -NoNewline; Write-Color $localIP "Yellow"
    Write-Color "Внешний IP   : " "White" -NoNewline; Write-Color $externalIP "Green"
    Write-Color "`n=============================================`n" "DarkGray"

    Write-Color "Выберите действие:" "Yellow"
    Write-Host "   1  — Сканирование соединений (Процессы и порты)"
    Write-Host "   2  — Проверка доступности РФ сервисов (russia.txt)"
    Write-Host "   3  — Проверка зарубежных сервисов (foreign.txt)"
    Write-Host "   4  — Выход"
    Write-Host "="*45

    $choice = Read-Host "Ваш выбор"

    switch ($choice) {
        "1" {
            Clear-Host
            Write-Color "=== АНАЛИЗ СЕТЕВОЙ АКТИВНОСТИ ===`n" "Green"
            $procTable = @{}
            Get-Process | ForEach-Object { $procTable[$_.Id] = $_.ProcessName }

            Write-Color "[+] Открытые порты (LISTENING):" "Yellow"
            $openPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
                Select-Object @{N='Порт'; E={$_.LocalPort}}, 
                              @{N='Процесс'; E={$procTable[$_.OwningProcess]}}, 
                              @{N='PID'; E={$_.OwningProcess}} | 
                Sort-Object Процесс

            if ($openPorts) { $openPorts | Format-Table -AutoSize } 
            else { Write-Color "   ! Запустите от имени АДМИНИСТРАТОРА для просмотра портов !`n" "Red" }

            Write-Color "[+] Активные внешние соединения (ESTABLISHED):" "Yellow"
            $connections = netstat -ano | findstr "ESTABLISHED" | ForEach-Object {
                $parts = $_.Trim() -split '\s+'
                if ($parts.Count -ge 5) {
                    $remote = $parts[2]
                    $cID = $parts[4]
                    if ($remote -notmatch "127.0.0.1|\[::1\]") {
                        [PSCustomObject]@{
                            'Локальный' = $parts[1]
                            'Удалённый' = $remote
                            'PID'       = $cID
                            'Процесс'   = if ($procTable.ContainsKey([int]$cID)) { $procTable[[int]$cID] } else { "Unknown" }
                        }
                    }
                }
            } | Sort-Object Процесс

            if ($connections) { $connections | Format-Table -AutoSize } 
            else { Write-Host "   Активных внешних соединений не найдено." }
            pause
        }
        
        { $_ -eq "2" -or $_ -eq "3" } {
            Clear-Host
            $file = if ($choice -eq "3") { "foreign.txt" } else { "russia.txt" }
            
            if (-not (Test-Path $file)) {
                Write-Color "Файл $file не найден! Создаю пустой..." "Red"
                "" | Out-File $file -Encoding UTF8
                pause
            } else {
                Write-Color "Проверка сервисов из $file :" "Yellow"
                $targets = Get-Content $file | Where-Object { $_.Trim() }
                if ($choice -eq "3") { $targets += @("youtube.com", "googlevideo.com") }

                if ($targets.Count -eq 0) { Write-Color "Список пуст. Добавьте домены в $file" "Gray" }

                foreach ($domain in $targets) {
                    Write-Host "- $domain " -NoNewline
                    try {
                        $tcp = New-Object System.Net.Sockets.TcpClient
                        $connect = $tcp.BeginConnect($domain, 443, $null, $null)
                        if ($connect.AsyncWaitHandle.WaitOne(2000, $false) -and $tcp.Connected) {
                            Write-Host "[ДОСТУПЕН]" -ForegroundColor Green
                        } else {
                            Write-Host "[НЕДОСТУПЕН]" -ForegroundColor Red
                        }
                        $tcp.Close()
                    } catch { Write-Host "[ОШИБКА]" -ForegroundColor DarkRed }
                }
                pause
            }
        }
        
        "4" { exit }
    }
} while ($true)
