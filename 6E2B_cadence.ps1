# ESP32-P4 Phase 6E.2B
# TX Latency Localization - Same-Boot Cadence Test
#
# IMPORTANT:
#   - Do not reboot/reset the ESP32 during this test.
#   - Start the ESP-IDF serial monitor BEFORE running this script.
#   - Leave ETH_NTP_TX_COMPENSATION_NS = 98941ULL unchanged.
#
# Sequence:
#   A. 60 s idle -> 1 request
#   B. 60 s idle -> 1 request
#   C. 60 s idle -> 20 requests at approximately 2 s cadence
#   D. 7 s idle  -> 1 request
#   E. 60 s idle -> 1 request
#
# Total expected NTP requests: 24

$Server = "192.168.2.54"

function Invoke-NtpSample {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $timestamp = Get-Date -Format "HH:mm:ss.fff"

    Write-Host ""
    Write-Host "[$timestamp] $Label"

    w32tm /stripchart /computer:$Server /dataonly /samples:1

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "w32tm returned exit code $LASTEXITCODE for: $Label"
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host " ESP32-P4 Phase 6E.2B - TX Latency Localization"
Write-Host " Target: $Server"
Write-Host "============================================================"
Write-Host ""
Write-Host "Do NOT reset the ESP32 during this sequence."
Write-Host ""


# ============================================================
# A
# 60 second idle followed by one NTP request
# ============================================================

Write-Host "[A] Idle 60 seconds..."
Start-Sleep -Seconds 60

Invoke-NtpSample "A - single request after >=60 s idle"


# ============================================================
# B
# Another 60 second idle followed by one NTP request
# ============================================================

Write-Host ""
Write-Host "[B] Idle 60 seconds..."
Start-Sleep -Seconds 60

Invoke-NtpSample "B - single request after >=60 s idle"


# ============================================================
# C
# 60 second idle followed by 20 NTP requests
# approximately 2 seconds apart
# ============================================================

Write-Host ""
Write-Host "[C] Idle 60 seconds before burst..."
Start-Sleep -Seconds 60

Write-Host ""
Write-Host "[C] Starting 20-request burst at ~2 second cadence..."

for ($i = 1; $i -le 20; $i++) {

    Invoke-NtpSample "C - burst request $i/20"

    if ($i -lt 20) {
        Start-Sleep -Seconds 2
    }
}


# ============================================================
# D
# Short idle followed by one NTP request
# ============================================================

Write-Host ""
Write-Host "[D] Idle 7 seconds..."
Start-Sleep -Seconds 7

Invoke-NtpSample "D - single request after short idle"


# ============================================================
# E
# Long idle followed by final NTP request
# ============================================================

Write-Host ""
Write-Host "[E] Idle 60 seconds..."
Start-Sleep -Seconds 60

Invoke-NtpSample "E - final request after >=60 s idle"


# ============================================================
# Complete
# ============================================================

Write-Host ""
Write-Host "============================================================"
Write-Host " 6E.2B CADENCE TEST COMPLETE"
Write-Host "============================================================"
Write-Host ""
Write-Host "Expected NTP requests: 24"
Write-Host ""
Write-Host "Save the complete ESP-IDF serial monitor output."
Write-Host ""
Write-Host "Required records:"
Write-Host "  TX LOC APP"
Write-Host "  TX LOC DMA"
Write-Host "  HW TX NTP compare"
Write-Host "  HW TX late compare"
Write-Host ""
Write-Host "Do NOT reboot or modify TX compensation before"
Write-Host "the monitor capture has been saved."
Write-Host ""