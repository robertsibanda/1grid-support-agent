# 1-grid AI Support Agent — Local Development Server (Windows)
# Run this from PowerShell in the project directory

Write-Host "=== 1-grid AI Support Agent (Local Dev) ===" -ForegroundColor Cyan
Write-Host ""

# Check if Ollama is running
$ollamaOk = $false
try {
    $resp = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -TimeoutSec 3 -ErrorAction SilentlyContinue
    if ($resp.StatusCode -eq 200) {
        $ollamaOk = $true
    }
} catch {}

if (-not $ollamaOk) {
    Write-Host "⚠ Ollama is not running on http://localhost:11434" -ForegroundColor Yellow
    Write-Host "  The API will start but diagnosis endpoint will fail until Ollama is available."
    Write-Host "  Install: https://ollama.com/download/windows"
    Write-Host "  Then: ollama pull llama3.1:8b"
    Write-Host ""
}

# Ingest KB articles into ChromaDB
Write-Host "→ Ingesting KB articles into ChromaDB..." -ForegroundColor Green
try {
    python -m app.rag.kb_ingest
    Write-Host "  KB ingestion complete" -ForegroundColor Green
} catch {
    Write-Host "  KB ingestion failed (non-fatal): $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "→ Starting FastAPI dev server..." -ForegroundColor Green
Write-Host "  API docs: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "  Health:   http://localhost:8000/health" -ForegroundColor Cyan
Write-Host ""

# Start uvicorn with hot reload
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
