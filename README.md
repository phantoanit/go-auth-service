# Server - Golang Backend

This directory contains the Golang backend microservice for the authentication service.

## Structure

```
server/
├── cmd/                    # Application entry points
│   └── main.go            # Main application
├── internal/              # Private application code
│   ├── domain/           # Domain models and business logic
│   ├── grpc/             # gRPC server implementation
│   ├── handler/          # HTTP handlers
│   ├── repository/       # Data access layer
│   ├── service/          # Business logic services
│   └── tests/            # Internal tests
├── proto/                # Protocol buffer definitions
├── go.mod                # Go module definition
├── go.sum                # Go module checksums
├── Dockerfile            # Docker container definition
├── Makefile              # Build automation
├── .env.example          # Environment variables template
└── README.md             # This file
```

## Getting Started

### Prerequisites

- Go >= 1.21
- PostgreSQL database
- Protocol Buffers compiler (protoc)

### Installation

1. Install dependencies:
```bash
cd server
go mod download
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Run database migrations (if applicable):
```bash
make migrate-up
```

### Development

Run the development server:
```bash
make run-dev
```

Or use the convenience scripts:
- **Windows**: `run-dev.bat` or `run-dev.ps1`
- **Unix/Linux/macOS**: `make run-dev`

### Build

Build the application:
```bash
make build
```

### Testing

Run tests:
```bash
make test
```

For Windows:
```bash
test-windows.bat
# or
test-windows.ps1
```

### Docker

Build Docker image:
```bash
docker build -t auth-service .
```

Run with Docker:
```bash
docker run -p 8080:8080 auth-service
```

## Features

- User authentication (JWT-based)
- OAuth2 integration
- Role-based access control (RBAC)
- Refresh token mechanism
- gRPC and REST API support
- PostgreSQL database integration
- Secure password hashing

## API Endpoints

### REST API
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/profile` - Get user profile

### gRPC Services
- See `proto/auth.proto` for service definitions

## Environment Variables

See `.env.example` for all available configuration options.

Key variables:
- `DB_HOST` - Database host
- `DB_PORT` - Database port
- `DB_USER` - Database user
- `DB_PASSWORD` - Database password
- `DB_NAME` - Database name
- `JWT_SECRET` - Secret key for JWT signing
- `SERVER_PORT` - Server port

## Technology Stack

- Go 1.21+
- gRPC
- PostgreSQL
- JWT authentication
- Protocol Buffers

## Windows Support

This service has full Windows support. See the documentation in `/docs`:
- `WINDOWS_SETUP.md`
- `WINDOWS_QUICKSTART.md`
- `WINDOWS_COMPATIBILITY.md`
- `WINDOWS_TEST_RESULTS.md`

## Contributing

Please read CONTRIBUTING.md in the root directory for details on our code of conduct and the process for submitting pull requests.

## Security

See SECURITY.md in the root directory for security considerations and reporting vulnerabilities.
