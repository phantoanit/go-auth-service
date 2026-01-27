# Windows Development Run Script for go-auth-service (PowerShell)
# This script runs the auth service in development mode

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting go-auth-service" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Go is installed
try {
    go version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw }
} catch {
    Write-Host "[ERROR] Go is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please run setup-windows.ps1 first" -ForegroundColor Red
    exit 1
}

# Check if .env file exists
if (-not (Test-Path .env)) {
    Write-Host "[WARNING] .env file not found" -ForegroundColor Yellow
    Write-Host "Please run setup-windows.ps1 first or create .env file" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Display configuration
Write-Host "[INFO] Starting service with configuration from .env" -ForegroundColor Cyan
Write-Host "[INFO] HTTP Port: Check AUTH_SERVICE_HTTP_PORT in .env (default: 8081)" -ForegroundColor Cyan
Write-Host "[INFO] gRPC Port: Check AUTH_SERVICE_PORT in .env (default: 50051)" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Health check: http://localhost:8081/health" -ForegroundColor Green
Write-Host "[INFO] Press Ctrl+C to stop the service" -ForegroundColor Yellow
Write-Host ""
Write-Host "----------------------------------------"
Write-Host ""

# Run the application
try {
    go run cmd/main.go
} catch {
    Write-Host ""
    Write-Host "[ERROR] Service failed to start" -ForegroundColor Red
    Write-Host ""
    Write-Host "Common issues:" -ForegroundColor Yellow
    Write-Host "- MongoDB is not running"
    Write-Host "- Redis is not running"
    Write-Host "- Port is already in use"
    Write-Host "- Invalid configuration in .env"
    Write-Host ""
    Write-Host "See WINDOWS_SETUP.md for troubleshooting"
    exit 1
}
