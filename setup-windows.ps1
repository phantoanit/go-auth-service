# Windows Setup Script for go-auth-service (PowerShell)
# This script helps set up the development environment on Windows

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  go-auth-service Windows Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Go is installed
Write-Host "[1/6] Checking Go installation..." -ForegroundColor Yellow
try {
    $goVersion = go version 2>&1
    Write-Host $goVersion -ForegroundColor Green
    Write-Host "[OK] Go is installed" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "[ERROR] Go is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Go from https://go.dev/dl/" -ForegroundColor Red
    exit 1
}

# Check if Git is installed
Write-Host "[2/6] Checking Git installation..." -ForegroundColor Yellow
try {
    $gitVersion = git --version 2>&1
    Write-Host $gitVersion -ForegroundColor Green
    Write-Host "[OK] Git is installed" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Git is not installed or not in PATH" -ForegroundColor Yellow
    Write-Host "Please install Git from https://git-scm.com/download/win" -ForegroundColor Yellow
}
Write-Host ""

# Download dependencies
Write-Host "[3/6] Downloading Go dependencies..." -ForegroundColor Yellow
try {
    go mod download
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "[OK] Dependencies downloaded" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to download dependencies" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Verify dependencies
Write-Host "[4/6] Verifying Go dependencies..." -ForegroundColor Yellow
try {
    go mod verify
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "[OK] Dependencies verified" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to verify dependencies" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Create .env file if it doesn't exist
Write-Host "[5/6] Setting up environment configuration..." -ForegroundColor Yellow
if (-not (Test-Path .env)) {
    if (Test-Path .env.example) {
        Copy-Item .env.example .env
        Write-Host "[OK] Created .env from .env.example" -ForegroundColor Green
        Write-Host "[ACTION REQUIRED] Please edit .env file with your configuration" -ForegroundColor Yellow
    } else {
        $envContent = @"
# Auth Service Configuration
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=auth_service
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
JWT_SECRET=your-secret-key-change-in-production
JWT_EXPIRATION=900
JWT_REFRESH_EXPIRATION=604800
AUTH_SERVICE_PORT=50051
AUTH_SERVICE_HTTP_PORT=8081
LOG_LEVEL=info
ENVIRONMENT=development
"@
        $envContent | Out-File -FilePath .env -Encoding UTF8
        Write-Host "[OK] Created default .env file" -ForegroundColor Green
        Write-Host "[ACTION REQUIRED] Please edit .env file with your configuration" -ForegroundColor Yellow
    }
} else {
    Write-Host "[OK] .env file already exists" -ForegroundColor Green
}
Write-Host ""

# Build the application
Write-Host "[6/6] Building the application..." -ForegroundColor Yellow
if (-not (Test-Path bin)) {
    New-Item -ItemType Directory -Path bin | Out-Null
}

try {
    go build -o bin/auth-service.exe ./cmd/main.go
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "[OK] Application built successfully: bin\auth-service.exe" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to build application" -ForegroundColor Red
    exit 1
}
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Edit .env file with your configuration"
Write-Host "2. Ensure MongoDB is running (locally or in Docker)"
Write-Host "3. Ensure Redis is running (locally or in Docker)"
Write-Host "4. Run the service with: .\run-dev.ps1"
Write-Host "5. Or run tests with: .\test-windows.ps1"
Write-Host ""
Write-Host "For more information, see WINDOWS_SETUP.md"
Write-Host ""
