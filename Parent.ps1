<#
.SYNOPSIS
  Send SMS messages to an HTTP gateway by processing files from a ready directory.

.DESCRIPTION
  - Reads files from $ReadyDir.
  - Extracts recipient phone number from the start of the filename (first continuous digits).
    Example filename: +36208235427.1234
  - Sends message body (file contents) to gateway via HTTP POST (form urlencoded by default).
  - If send succeeds, moves file to $SentDir.
  - If send fails, increments attempt count (persisted in companion .retry file).
  - After $MaxRetries attempts, moves file to $DlqDir (dead-letter queue).

.NOTES
  - Requires PowerShell 7+ (Invoke-RestMethod improvements & reliable -TimeoutSec).
  - Provide $BaseDir, $GatewayHost etc. as parameters or use the provided defaults.
#>

# -------------------------
# Command line parameters - with sensible defaults
# -------------------------
param (
    [string]$BaseDir        = "$HOME/bms/sms",
    [string]$GatewayHost    = "http://localhost:8200",
    [switch]$RunContinuous    # if given the script will loop and sleep; otherwise processes current files then exits
)

# -------------------------
# Configuration - edit as needed
# -------------------------
$LoginEndpoint          = "$GatewayHost/api/login"
$SessionStatusEndpoint  = "$GatewayHost/api/session/status"
# $AuthToken       = $null # Variable to hold token during run
$AuthToken              = "263563a46a611563fb8c23145d6a25d7"
$ReadyDir               = "$BaseDir/ready"
$ProcessingDir          = "$BaseDir/processing" # Temporary lock/move location while processing
$SentDir                = "$BaseDir/sent"
$DlqDir                 = "$BaseDir/dlq"
$SleepBetweenLoops      = 15    # Seconds when running continuous

# -------------------------
# Setup directories
# -------------------------
foreach ($d in @($ReadyDir, $ProcessingDir, $SentDir, $DlqDir)) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

# -------------------------
# Get credentials for API calls
# -------------------------
# Save credential once
# $cred = Get-Credential  # Enter <user_name> / <password>
# $cred | Export-Clixml -Path "$HOME/.apiCred.xml"

$cred = Import-Clixml -Path "$HOME/.apiCred.xml"
$ApiUser = $cred.UserName
$ApiPassword = $cred.GetNetworkCredential().Password

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "info"
    )

    if ($IsWindows) {
        Write-EventLog -LogName Application -Source "SMS-Script" -EventId 1000 -EntryType Information -Message $Message
    } else {
        & logger -p "user.$Level" "sms-script: $Message"
    }
}

# -------------------------
# Function: Login and acquire an auth token for further use.
# -------------------------
function Get-AuthToken {
    if ($AuthToken) {
        return $AuthToken
    }

    $loginBody = @{
        username = $ApiUser
        password = $ApiPassword
    } | ConvertTo-Json -Depth 3

    try {
        $loginResponse = Invoke-RestMethod -Uri $LoginEndpoint `
                                        -Method Post `
                                        -Body $loginBody `
                                        -ContentType "application/json" `
                                        -SkipCertificateCheck `
                                        -TimeoutSec 30

        # Expecting { success: true, data: { username, token, expires } }
        $token = $loginResponse.data.token

        if (-not $token) {
            throw "Login succeeded but no bearer token found in response"
        }

        $AuthToken = $token
        Write-Host "Obtained bearer token for $($loginResponse.data.username)." -ForegroundColor Cyan
        
        return $token
    } catch {
        throw "Failed to login: $($_.Exception.Message)"
    }
}

function Check-SessionStatus {

    return $true

    try {
        $headers = @{
            "Authorization" = "Bearer $AuthToken"
            "Content-Type"  = "application/json"
        }

        $response = Invoke-RestMethod -Uri $SessionStatusEndpoint -Method Get -Headers $headers -SkipCertificateCheck

        if ($null -eq $response) {
            Write-Warning "No response from session status endpoint."
            return $false
        }

        if ($response.success -eq $true -and $response.data.active -eq $true) {
            Write-Host "✅ Session is active" -ForegroundColor Green
            return $true
        } else {
            Write-Host "⚠️ Session is inactive" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Error "Failed to check session status: $_"
        return $false
    }
}

function Get-ReadyFiles {
    return Get-ChildItem -Path $ReadyDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.\d+$' } | Sort-Object LastWriteTime
}

# -------------------------
# Run once or continuously
# -------------------------
do {
    $AuthToken = Get-AuthToken

    Get-ReadyFiles | ForEach-Object -Parallel {
        # pwsh ./Child.ps1 -AuthToken $using:bearerToken -ReadyFile $_.FullName
        & ./Child.ps1 -AuthToken $using:AuthToken -ReadyFile $_.FullName
    } -ThrottleLimit 5

    if ($RunContinuous) {
        Start-Sleep -Seconds $SleepBetweenLoops
        if (-not (Check-SessionStatus)) {
            $AuthToken = $null
        }
    }
} while ($RunContinuous)

Write-Host "Processing finished (RunContinuous = $RunContinuous)."