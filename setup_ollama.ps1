# Ollama Config - Uses qwen3:8b for all tasks

Write-Host "=== Ollama Configuration ===" -ForegroundColor Cyan

$ollamaCheck = ollama --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Ollama not installed. Get from https://ollama.com/download/windows" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] $ollamaCheck" -ForegroundColor Green

# Verify qwen3:8b exists
$models = ollama list 2>&1
if ($models -notmatch "qwen3:8b") {
    Write-Host "qwen3:8b not found. Pulling..." -ForegroundColor Yellow
    ollama pull qwen3:8b
}
Write-Host "[OK] qwen3:8b available" -ForegroundColor Green

$env:LLM_PROVIDER = "ollama"
$env:LLM_BASE_URL = "http://localhost:11434"
$env:LLM_SMALL_MODEL = "qwen3:8b"
$env:LLM_LARGE_MODEL = "qwen3:8b"

Write-Host "`n=== Session Config ===" -ForegroundColor Green
Write-Host "Model: qwen3:8b (both tiers)"

Write-Host "`nTo persist across sessions:" -ForegroundColor Gray
Write-Host "  setx LLM_SMALL_MODEL qwen3:8b"
Write-Host "  setx LLM_LARGE_MODEL qwen3:8b"

Write-Host "`nTo add a faster small model later:" -ForegroundColor Gray
Write-Host "  ollama pull qwen2.5:3b"
Write-Host "  `$env:LLM_SMALL_MODEL='qwen2.5:3b'"

Write-Host "`nRun:" -ForegroundColor Cyan
Write-Host "  python main.py --target https://juice-shop.herokuapp.com/#/ --mode PASSIVE"