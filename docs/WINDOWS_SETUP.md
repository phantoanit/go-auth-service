# Windows Development Environment Setup Guide

> Hướng dẫn cài đặt và phát triển go-auth-service trên Windows

## Mục lục

- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Cài đặt công cụ cần thiết](#cài-đặt-công-cụ-cần-thiết)
- [Cài đặt dự án](#cài-đặt-dự-án)
- [Chạy ứng dụng](#chạy-ứng-dụng)
- [Chạy tests](#chạy-tests)
- [Khắc phục sự cố](#khắc-phục-sự-cố)

## Yêu cầu hệ thống

### Hệ điều hành
- Windows 10 (version 1903+) hoặc Windows 11
- Windows Server 2019 hoặc mới hơn

### Phần cứng tối thiểu
- CPU: 2 cores
- RAM: 4GB (khuyến nghị 8GB)
- Ổ cứng: 5GB dung lượng trống

## Cài đặt công cụ cần thiết

### 1. Git cho Windows

**Tải về và cài đặt:**
```
URL: https://git-scm.com/download/win
```

**Cấu hình sau khi cài đặt:**
```cmd
git config --global core.autocrlf true
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

**Lưu ý:** Chọn "Git from the command line and also from 3rd-party software" trong quá trình cài đặt.

### 2. Go (Golang)

**Phiên bản yêu cầu:** Go 1.25.5 trở lên

**Tải về và cài đặt:**
```
URL: https://go.dev/dl/
```

Tải file `.msi` cho Windows (ví dụ: `go1.25.5.windows-amd64.msi`)

**Kiểm tra cài đặt:**
```cmd
go version
```

Kết quả mong đợi:
```
go version go1.25.5 windows/amd64
```

**Cấu hình biến môi trường (đã tự động trong installer):**
- `GOROOT`: `C:\Program Files\Go`
- `GOPATH`: `%USERPROFILE%\go`
- Đường dẫn `%GOPATH%\bin` và `%GOROOT%\bin` đã được thêm vào PATH

**Kiểm tra biến môi trường:**
```cmd
echo %GOROOT%
echo %GOPATH%
go env
```

### 3. Make cho Windows (Optional nhưng khuyến nghị)

**Cách 1: Cài đặt qua Chocolatey (khuyến nghị)**
```powershell
# Cài đặt Chocolatey (nếu chưa có)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Cài đặt Make
choco install make
```

**Cách 2: Cài đặt qua scoop**
```powershell
# Cài đặt Scoop (nếu chưa có)
iwr -useb get.scoop.sh | iex

# Cài đặt Make
scoop install make
```

**Cách 3: Sử dụng MinGW/MSYS2**
```
URL: https://www.msys2.org/
```

**Kiểm tra cài đặt:**
```cmd
make --version
```

### 4. Docker Desktop for Windows (Optional - cho containerization)

**Yêu cầu:**
- WSL 2 (Windows Subsystem for Linux)
- Hyper-V được bật

**Tải về và cài đặt:**
```
URL: https://www.docker.com/products/docker-desktop/
```

**Kiểm tra cài đặt:**
```cmd
docker --version
docker-compose --version
```

**Lưu ý quan trọng:**
- Chọn "Use WSL 2 instead of Hyper-V" khi cài đặt
- Khởi động Docker Desktop trước khi chạy lệnh Docker

### 5. MongoDB (Optional - cho development)

**Cách 1: MongoDB Community Server**
```
URL: https://www.mongodb.com/try/download/community
```

**Cách 2: Chạy MongoDB trong Docker**
```cmd
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

### 6. Redis (Optional - cho development)

**Chạy Redis trong Docker:**
```cmd
docker run -d -p 6379:6379 --name redis redis:latest
```

**Hoặc sử dụng Memurai (Redis for Windows):**
```
URL: https://www.memurai.com/get-memurai
```

## Cài đặt dự án

### 1. Clone repository

```cmd
git clone https://github.com/vhvplatform/go-auth-service.git
cd go-auth-service
```

### 2. Cài đặt dependencies

```cmd
go mod download
go mod verify
```

### 3. Cấu hình môi trường

**Tạo file `.env` từ template:**
```cmd
copy .env.example .env
```

**Chỉnh sửa file `.env` với thông tin của bạn:**
```env
# Database Configuration
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=auth_service

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# JWT Configuration
JWT_SECRET=your-secret-key-here
JWT_EXPIRATION=900
JWT_REFRESH_EXPIRATION=604800

# Service Ports
AUTH_SERVICE_PORT=50051
AUTH_SERVICE_HTTP_PORT=8081

# Logging
LOG_LEVEL=info

# Environment
ENVIRONMENT=development
```

## Chạy ứng dụng

### Phương pháp 1: Sử dụng Go trực tiếp

**Command Prompt (CMD):**
```cmd
go run cmd/main.go
```

**PowerShell:**
```powershell
go run cmd/main.go
```

### Phương pháp 2: Sử dụng Makefile (nếu đã cài Make)

```cmd
make build
.\bin\auth-service.exe
```

### Phương pháp 3: Sử dụng batch script

```cmd
run-dev.bat
```

### Phương pháp 4: Sử dụng Docker

```cmd
docker build -t auth-service .
docker run -p 50051:50051 -p 8081:8081 auth-service
```

### Kiểm tra service đang chạy

**Kiểm tra HTTP endpoint:**
```cmd
curl http://localhost:8081/health
```

**Hoặc mở trình duyệt:**
```
http://localhost:8081/health
```

Kết quả mong đợi:
```json
{"status":"healthy"}
```

## Chạy tests

### Chạy tất cả tests

**Command Prompt:**
```cmd
go test ./...
```

**PowerShell:**
```powershell
go test ./...
```

**Với Makefile:**
```cmd
make test
```

**Với batch script:**
```cmd
test-windows.bat
```

### Chạy tests với coverage

```cmd
go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
go tool cover -html=coverage.txt -o coverage.html
```

Sau đó mở file `coverage.html` trong trình duyệt.

### Chạy tests cho package cụ thể

```cmd
go test -v ./internal/service
go test -v ./internal/handler
go test -v ./internal/repository
```

### Chạy test verification cho Windows

```cmd
go test -v -run TestWindowsEnvironment ./internal/tests
```

## Khắc phục sự cố

### 1. Lỗi "go: command not found"

**Nguyên nhân:** Go chưa được thêm vào PATH

**Giải pháp:**
1. Mở "System Properties" > "Environment Variables"
2. Thêm `C:\Program Files\Go\bin` vào PATH
3. Khởi động lại Command Prompt

### 2. Lỗi "cannot find package"

**Nguyên nhân:** Dependencies chưa được tải về

**Giải pháp:**
```cmd
go mod download
go mod tidy
go mod verify
```

### 3. Lỗi line endings (CRLF vs LF)

**Nguyên nhân:** Windows sử dụng CRLF, Unix sử dụng LF

**Giải pháp:**
```cmd
git config --global core.autocrlf true
```

Sau đó clone lại repository hoặc refresh:
```cmd
git rm --cached -r .
git reset --hard
```

### 4. Lỗi "Access is denied" khi build

**Nguyên nhân:** Antivirus hoặc Windows Defender đang block

**Giải pháp:**
1. Thêm thư mục dự án vào exclusion list của antivirus
2. Hoặc thêm `%GOPATH%\bin` vào exclusion list

### 5. Lỗi kết nối MongoDB

**Lỗi:** `connection refused` hoặc `no reachable servers`

**Giải pháp:**
1. Kiểm tra MongoDB đang chạy:
   ```cmd
   tasklist | findstr mongod
   ```
2. Khởi động MongoDB:
   ```cmd
   net start MongoDB
   ```
3. Hoặc chạy MongoDB trong Docker:
   ```cmd
   docker start mongodb
   ```

### 6. Lỗi kết nối Redis

**Lỗi:** `connection refused`

**Giải pháp:**
1. Kiểm tra Redis đang chạy:
   ```cmd
   docker ps | findstr redis
   ```
2. Khởi động Redis:
   ```cmd
   docker start redis
   ```

### 7. Port đã được sử dụng

**Lỗi:** `bind: address already in use`

**Giải pháp Windows:**
```cmd
# Tìm process đang sử dụng port
netstat -ano | findstr :8081
netstat -ano | findstr :50051

# Kill process theo PID
taskkill /PID <PID> /F
```

### 8. Lỗi "make: command not found"

**Nguyên nhân:** Make chưa được cài đặt

**Giải pháp:**
1. Sử dụng batch scripts thay vì Makefile
2. Hoặc cài đặt Make như hướng dẫn ở trên
3. Hoặc chạy lệnh Go trực tiếp

### 9. Lỗi CGO khi build

**Lỗi:** `gcc: not found` hoặc CGO errors

**Giải pháp:**
Build với CGO disabled (mặc định cho service này):
```cmd
set CGO_ENABLED=0
go build -o bin/auth-service.exe ./cmd/main.go
```

### 10. Lỗi Docker Desktop không khởi động

**Nguyên nhân:** WSL 2 chưa được cài đặt hoặc cấu hình

**Giải pháp:**
```powershell
# Chạy với quyền Administrator
wsl --install
wsl --set-default-version 2
```

Sau đó khởi động lại máy.

## Kiểm tra môi trường Windows

Chạy script kiểm tra tự động:

```cmd
go run internal/tests/windows_check.go
```

Script này sẽ kiểm tra:
- ✓ Go version và cấu hình
- ✓ Dependencies có thể tải về và sử dụng
- ✓ Các port cần thiết có sẵn
- ✓ Build thành công
- ✓ Tests chạy thành công

## Các lệnh thường dùng

### Build commands

```cmd
# Build for Windows
go build -o bin/auth-service.exe ./cmd/main.go

# Build với optimizations
go build -ldflags="-s -w" -o bin/auth-service.exe ./cmd/main.go

# Cross-compile cho Linux từ Windows
set GOOS=linux
set GOARCH=amd64
go build -o bin/auth-service ./cmd/main.go
```

### Development commands

```cmd
# Format code
go fmt ./...

# Vet code
go vet ./...

# Run linter (nếu đã cài golangci-lint)
golangci-lint run

# Update dependencies
go get -u ./...
go mod tidy
```

## Tài liệu tham khảo

- [Go on Windows](https://go.dev/doc/install/windows)
- [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
- [WSL 2 Installation](https://docs.microsoft.com/en-us/windows/wsl/install)
- [Main README](README.md)

## Hỗ trợ

Nếu gặp vấn đề không được giải quyết trong tài liệu này:

1. Kiểm tra [GitHub Issues](https://github.com/vhvplatform/go-auth-service/issues)
2. Tạo issue mới với:
   - Hệ điều hành và phiên bản Windows
   - Go version (`go version`)
   - Lỗi đầy đủ và steps để tái tạo
3. Tham gia [GitHub Discussions](https://github.com/vhvplatform/go-auth-service/discussions)
