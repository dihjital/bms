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
    # [string]$GatewayHost    = "https://198.1.1.237",

    [Parameter(Mandatory=$true)]
    [string]$AuthToken,

    [Parameter(Mandatory=$true)]
    [string]$ReadyFile,

    [int]$MaxRetries        = 3
)

# -------------------------
# Configuration - edit as needed
# -------------------------
$SendEndpoint         = "$GatewayHost/api/messages/actions/send"
$Modem                = "3-1"

$ReadyDir             = "$BaseDir/ready"
$ProcessingDir        = "$BaseDir/processing"   # temporary lock/move location while processing
$SentDir              = "$BaseDir/sent"
$DlqDir               = "$BaseDir/dlq"

$RetryDelaySeconds    = 10      # base delay between retries
$RetryFileExtension   = '.retry' # companion file storing attempt count (same filename + .retry)

# -------------------------
# Setup directories
# -------------------------
foreach ($d in @($ReadyDir, $ProcessingDir, $SentDir, $DlqDir)) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

# -------------------------
# Helper functions
# -------------------------
function Get-PhoneFromFilename {
    param($FileName)
    # Extract first continuous sequence of digits from start of filename
    # Accepts filenames like: +36208235427.1234
    if ($FileName -match '^(\+\d+)') { return $matches[1] }
    return $null
}

function Read-RetryCount {
    param($FilePath)
    $retryFile = "${FilePath}${RetryFileExtension}"
    if (Test-Path $retryFile) {
        try {
            $text = Get-Content -Path $retryFile -Raw -ErrorAction Stop
            [int]::TryParse($text.Trim(), [ref]$val) | Out-Null
            return $val
        } catch { return 0 }
    }
    return 0
}

function Write-RetryCount {
    param($FilePath, [int]$Count)
    $retryFile = "${FilePath}${RetryFileExtension}"
    Set-Content -Path $retryFile -Value $Count -Encoding UTF8
}

function Remove-RetryFile {
    param($FilePath)
    $retryFile = "${FilePath}${RetryFileExtension}"
    if (Test-Path $retryFile) { Remove-Item $retryFile -Force -ErrorAction SilentlyContinue }
}

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
# Function: Send SMS (with auto re-login on 401)
# -------------------------
function Try-SendMessage {
    param(
        [string]$Phone,
        [string]$Text
    )

    $sendBody = @{
        data = @{
            number  = "+$Phone"   # ensure leading + if required
            message = $Text
            modem   = $Modem
        }
    } | ConvertTo-Json -Depth 5

    while ($true) {
        try {            
            $headers = @{
                "Authorization" = "Bearer $AuthToken"
            }

            $sendResponse = Invoke-RestMethod -Uri $SendEndpoint `
                                              -Method Post `
                                              -Body $sendBody `
                                              -ContentType "application/json" `
                                              -Headers $headers `
                                              -SkipCertificateCheck `
                                              -TimeoutSec 30

            return @{ Success = $true; Response = $sendResponse }
        } catch {
            $ex = $_.Exception
            return @{ Success = $false; Error = $ex.Message; Exception = $ex }
        }
    }
}

# -------------------------
# Main file processing loop (single pass)
# -------------------------
function Process-ReadyFile {
    param([string]$FileToProcess)

    $file = [System.IO.FileInfo]::new($FileToProcess)
    $srcPath = $file.FullName

    # Attempt to move to processing directory to lock it for this run
    $processingPath = Join-Path $ProcessingDir $file.Name
    try {
        Move-Item -LiteralPath $srcPath -Destination $processingPath -Force -ErrorAction Stop
    } catch {
        # Could not move (maybe another process), skip
        Write-Host "Skipping $($file.Name) - could not acquire lock/move to processing. ($_)" -ForegroundColor Yellow
        continue
    }

    try {
        # Extract phone number
        $phone = Get-PhoneFromFilename -FileName $file.Name
        if (-not $phone) {
            Write-Host "No leading phone number found in filename '$($file.Name)'. Moving to dlq." -ForegroundColor Yellow
            $dest = Join-Path $DlqDir $file.Name
            Move-Item -Path $processingPath -Destination $dest -Force
            Remove-RetryFile -FilePath $processingPath
            continue
        }

        # Read message body
        $body = Get-Content -Path $processingPath -Raw -ErrorAction Stop

        # Read attempts so far
        $attempts = Read-RetryCount -FilePath $processingPath

        $sent = $false
        while ($attempts -lt $MaxRetries -and -not $sent) {
            $attempts++
            Write-Host "Sending $($file.Name) attempt $attempts/$MaxRetries to $phone ..."
            $result = Try-SendMessage -Phone $phone -Text $body

            if ($result.Success) {
                Write-Host "Send succeeded for $($file.Name)." -ForegroundColor Green
                # Move to sent
                $dest = Join-Path $SentDir $file.Name
                Move-Item -Path $processingPath -Destination $dest -Force
                Remove-RetryFile -FilePath $processingPath
                $sent = $true
            } else {
                # Log error
                Write-Host "Send failed for $($file.Name) attempt ${attempts}: $($result.Error)" -ForegroundColor Red
                # Persist attempts
                Write-RetryCount -FilePath $processingPath -Count $attempts

                if ($attempts -ge $MaxRetries) {
                    Write-Host "Max attempts reached for $($file.Name). Moving to DLQ." -ForegroundColor Yellow
                    $dest = Join-Path $DlqDir $file.Name
                    Move-Item -Path $processingPath -Destination $dest -Force
                    Remove-RetryFile -FilePath $processingPath
                    break
                } else {
                    # Exponential backoff-ish delay
                    $delay = [int]($RetryDelaySeconds * [math]::Pow(2, ($attempts - 1)))
                    Write-Host "Waiting $delay seconds before next attempt..."
                    Start-Sleep -Seconds $delay
                    # Continue loop to retry
                }
            }
        } # end while
    } catch {
        # Unexpected exception while processing - move to dlq to avoid infinite loop
        Write-Host "Unexpected error processing $($file.Name): $_" -ForegroundColor Red
        try {
            $dest = Join-Path $DlqDir $file.Name
            Move-Item -Path $processingPath -Destination $dest -Force
            Remove-RetryFile -FilePath $processingPath
        } catch {
            Write-Host "Also failed to move to DLQ: $_" -ForegroundColor Red
        }
    }
}

# -------------------------
# Do the main thing
# -------------------------
Process-ReadyFile -fileToProcess $ReadyFile

Write-Host "Processing finished for file $ReadyFile."