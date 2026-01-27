# Build stage
FROM golang:1.25.5-alpine AS builder

WORKDIR /app

# Cài đặt các công cụ cần thiết
RUN apk add --no-cache git

# 1. Copy go.mod và go.sum của cả SHARED và SERVICE để cache dependencies
COPY go-shared/go.mod go-shared/go.sum ./go-shared/
COPY go-auth-service/go.mod go-auth-service/go.sum ./go-auth-service/

# 2. Download dependencies (Go sẽ tự xử lý mối quan hệ giữa các module)
WORKDIR /app/go-auth-service
RUN go mod edit -replace github.com/vhvplatform/go-shared=../go-shared
RUN go mod download

# 3. Copy toàn bộ mã nguồn cần thiết
WORKDIR /app
COPY go-shared/ ./go-shared/
COPY go-auth-service/ ./go-auth-service/

# 4. Build service
WORKDIR /app/go-auth-service
RUN go mod edit -replace github.com/vhvplatform/go-shared=../go-shared

RUN CGO_ENABLED=0 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags="-w -s" \
    -trimpath \
    -o /app/bin/auth-service ./cmd/main.go

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
RUN addgroup -S appgroup && adduser -S appuser -u 1000 -G appgroup
WORKDIR /app
RUN chown 1000:1000 /app
COPY --from=builder --chown=1000:1000 /app/bin/auth-service .
USER 1000
EXPOSE 50051 8081
CMD ["./auth-service"]
