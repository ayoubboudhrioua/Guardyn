# Evidence loop for Windows. Run from the defense repo.
#   .\run_matrix.ps1 -Kit C:\dev\Sentinel_Starter_Kit
param(
  [Parameter(Mandatory = $true)][string]$Kit,
  [string]$Port = "8080"
)
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$here = $PSScriptRoot

$ablations = @(
  "",                                   # full system
  "TOOL_NOT_IN_CONTRACT",
  "UNTRUSTED_CUSTODY",
  "FLOW_VIOLATION",
  "UNTRUSTED_INSTRUCTION_SOURCE",
  "MISSING_CONFIRMATION",
  "LIFECYCLE_SKIPPED",
  "CONTAINED_AT_SINK",
  "UNTRUSTED_CUSTODY,UNTRUSTED_INSTRUCTION_SOURCE,FLOW_VIOLATION"   # whole custody judge
)

foreach ($ab in $ablations) {
  $label = if ($ab -eq "") { "full-system" } else { $ab }
  $env:SENTINEL_ABLATE = $ab
  $env:SENTINEL_TRACE = Join-Path $here "observability\ablate-$($label -replace '[,]','+').jsonl"

  $server = Start-Process -PassThru -WindowStyle Hidden -FilePath "$here\.venv\Scripts\python.exe" `
            -ArgumentList "-m", "uvicorn", "app.main:app", "--port", $Port
  Start-Sleep -Seconds 5
  try {
    foreach ($split in @("public", "validation")) {
      Push-Location $Kit
      $json = uv run sentinel eval $split --defense-url "http://127.0.0.1:$Port" --json
      Pop-Location
      $m = ($json | ConvertFrom-Json).metrics
      "{0,-62} {1,-11} BTU={2:N3} ASR={3:N3} CVR={4:N3} FBR={5:N3} UER={6:N3} BRIER={7:N3}" -f `
        $label, $split, $m.btu, $m.asr, $m.cvr, $m.fbr, $m.uer, $m.brier
    }
  } finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
  }
}
