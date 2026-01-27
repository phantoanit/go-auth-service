# Windows Quick Start Guide

> Hướng dẫn nhanh cho developers Windows

## Cài đặt nhanh (5 phút)

### 1. Cài đặt Go
Tải và cài đặt Go 1.25+ từ: https://go.dev/dl/

### 2. Clone repository
```cmd
git clone https://github.com/vhvplatform/go-auth-service.git
cd go-auth-service
```

### 3. Chạy setup
```cmd
setup-windows.bat
```

### 4. Chỉnh sửa .env
Mở file `.env` và cập nhật cấu hình (nếu cần)

### 5. Chạy service
```cmd
run-dev.bat
```

## Các lệnh quan trọng

| Tác vụ | Command Prompt | PowerShell | Makefile |
|--------|---------------|------------|----------|
| Setup ban đầu | `setup-windows.bat` | `.\setup-windows.ps1` | N/A |
| Chạy service | `run-dev.bat` | `.\run-dev.ps1` | `make run` |
| Chạy tests | `test-windows.bat` | `.\test-windows.ps1` | `make test` |
| Build | `build-windows.bat` | `go build -o bin\auth-service.exe .\cmd\main.go` | `make build-windows` |
| Clean | `make clean` | `make clean` | `make clean` |

## Kiểm tra service đang chạy

### Health Check (HTTP)
```cmd
curl http://localhost:8081/health
```

Hoặc mở trình duyệt: http://localhost:8081/health

### Expected Response
```json
{"status":"healthy"}
```

## Dependencies ngoài

### MongoDB (chọn 1 trong 2)

**Option A: Docker (khuyến nghị)**
```cmd
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

**Option B: Native Install**
Tải từ: https://www.mongodb.com/try/download/community

### Redis (chọn 1 trong 2)

**Option A: Docker (khuyến nghị)**
```cmd
docker run -d -p 6379:6379 --name redis redis:latest
```

**Option B: Memurai (Redis for Windows)**
Tải từ: https://www.memurai.com/get-memurai

## Xử lý lỗi nhanh

### Lỗi: "go: command not found"
- Go chưa được cài hoặc không có trong PATH
- **Fix**: Cài đặt Go và restart Command Prompt

### Lỗi: "Port already in use"
```cmd
# Tìm process đang dùng port
netstat -ano | findstr :8081

# Kill process
taskkill /PID <PID> /F
```

### Lỗi: "Cannot connect to MongoDB"
```cmd
# Kiểm tra MongoDB đang chạy
docker ps | findstr mongodb

# Hoặc
tasklist | findstr mongod

# Khởi động MongoDB
docker start mongodb
# Hoặc
net start MongoDB
```

### Lỗi: "Cannot connect to Redis"
```cmd
# Kiểm tra Redis đang chạy
docker ps | findstr redis

# Khởi động Redis
docker start redis
```

## Cấu trúc file quan trọng

```
go-auth-service/
├── cmd/main.go              # Entry point
├── .env                     # Configuration (tạo từ .env.example)
├── WINDOWS_SETUP.md         # Chi tiết setup Windows
├── WINDOWS_COMPATIBILITY.md # Thông tin compatibility
├── setup-windows.bat        # Setup script (CMD)
├── setup-windows.ps1        # Setup script (PowerShell)
├── run-dev.bat             # Run script (CMD)
├── run-dev.ps1             # Run script (PowerShell)
├── test-windows.bat        # Test script (CMD)
└── test-windows.ps1        # Test script (PowerShell)
```

## Môi trường phát triển

### Khuyến nghị cho Windows

1. **IDE/Editor**
   - VS Code (khuyến nghị) với Go extension
   - GoLand
   - Vim/Neovim với vim-go

2. **Terminal**
   - Windows Terminal (khuyến nghị)
   - PowerShell 7+
   - Git Bash
   - Command Prompt

3. **Docker**
   - Docker Desktop for Windows với WSL 2

## Testing

### Chạy tất cả tests
```cmd
go test ./...
```

### Chạy tests cụ thể
```cmd
go test ./internal/tests -v
go test ./internal/domain -v
```

### Với coverage
```cmd
go test -coverprofile=coverage.txt ./...
go tool cover -html=coverage.txt -o coverage.html
start coverage.html
```

## Build cho production

### Build cho Windows
```cmd
set CGO_ENABLED=0
go build -ldflags="-s -w" -o bin\auth-service.exe .\cmd\main.go
```

### Cross-compile cho Linux
```cmd
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0
go build -ldflags="-s -w" -o bin\auth-service .\cmd\main.go
```

## Tài liệu đầy đủ

- [WINDOWS_SETUP.md](WINDOWS_SETUP.md) - Hướng dẫn chi tiết
- [WINDOWS_COMPATIBILITY.md](WINDOWS_COMPATIBILITY.md) - Thông tin compatibility
- [README.md](README.md) - Tài liệu tổng quan

## Support

Gặp vấn đề? Tham khảo:
1. [WINDOWS_SETUP.md - Troubleshooting section](WINDOWS_SETUP.md#khắc-phục-sự-cố)
2. [GitHub Issues](https://github.com/vhvplatform/go-auth-service/issues)
3. [GitHub Discussions](https://github.com/vhvplatform/go-auth-service/discussions)

## Tips cho Windows Developers

1. **Sử dụng Windows Terminal** cho trải nghiệm tốt hơn
2. **Bật WSL 2** cho Docker Desktop
3. **Cài Make qua Chocolatey** để sử dụng Makefile
4. **Dùng Git Bash** nếu quen với Unix commands
5. **PowerShell scripts** có màu sắc và format đẹp hơn batch scripts
