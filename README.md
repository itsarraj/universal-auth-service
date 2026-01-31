# 🚀 Universal Auth Service (UAS)

A **production-ready, enterprise-grade authentication microservice** built with **Rust**, **PostgreSQL**, and **Redis**. Designed for microservices architectures with JWT-based authentication, role-based access control, and comprehensive security features.

[![Rust](https://img.shields.io/badge/Rust-1.70+-000000?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-13+-4169E1?style=for-the-badge&logo=postgresql)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-6+-DC382D?style=for-the-badge&logo=redis)](https://redis.io/)
[![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=json-web-tokens)](https://jwt.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)](https://www.docker.com/)

## ✅ What this service gives you (in plain words)

UAS is a **central authentication service** you run once and reuse across all your applications/services.

- **Your apps stop storing passwords or issuing tokens** — they call UAS for auth flows (register/login/refresh/logout) and then use the returned **JWT access token** to protect their own APIs.
- **PostgreSQL stores permanent identity data** (users, refresh tokens, blacklist/audit tables).
- **Redis handles fast/temporary auth data** (rate limiting counters, user cache, token blacklist).

## 📋 Table of Contents

- [✨ Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [🔧 Prerequisites](#-prerequisites)
- [⚡ Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [⚙️ Configuration](#️-configuration)
- [🚀 Usage](#-usage)
- [📚 API Documentation](#-api-documentation)
- [🧪 Testing](#-testing)
- [🐳 Docker Deployment](#-docker-deployment)
- [🔒 Security](#-security)
- [📊 Monitoring & Health Checks](#-monitoring--health-checks)
- [🔧 Development](#-development)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## ✨ Features

### 🔐 Core Authentication
- ✅ **User Registration** with email verification
- ✅ **JWT Authentication** with access/refresh tokens
- ✅ **Password Reset** with secure token flow
- ✅ **Email Verification** for account activation
- ✅ **Secure Logout** with token blacklisting

### 👥 User Management
- ✅ **Profile Management** (view/update profile)
- ✅ **Password Change** with current password verification
- ✅ **Role-Based Access Control** (RBAC)
- ✅ **User Sessions** with Redis caching

### 🛡️ Security Features
- ✅ **bcrypt Password Hashing** (industry standard)
- ✅ **JWT Token Security** with expiration and rotation
- ✅ **Rate Limiting** (brute force protection)
- ✅ **Token Blacklisting** (prevent reuse)
- ✅ **CORS Support** for web applications
- ✅ **Input Validation** and sanitization

### 🚀 Performance & Scalability
- ✅ **Redis Caching** for high performance
- ✅ **Connection Pooling** (PostgreSQL + Redis)
- ✅ **Horizontal Scaling** ready
- ✅ **Stateless Design** for microservices
- ✅ **Health Monitoring** with detailed metrics

### 🏢 Production Ready
- ✅ **Comprehensive Logging** and error handling
- ✅ **Database Migrations** with rollback support
- ✅ **Automated Testing** suite
- ✅ **API Documentation** (Postman collection)
- ✅ **Docker Support** for containerization

## 🏗️ Architecture

### 3-Layer Architecture Pattern

```
┌─────────────────┐  ← HTTP Layer
│   Handlers      │  • HTTP request/response
│   (actix-web)   │  • Input validation
│                 │  • Error formatting
└─────────────────┘

         ↓ (calls)

┌─────────────────┐  ← Business Logic Layer
│   Services      │  • Authentication logic
│                 │  • Business rules
│                 │  • Orchestration
└─────────────────┘

         ↓ (uses)

┌─────────────────┬─────────────────┐  ← Data Layer
│  Repository     │   Cache         │  • PostgreSQL: persistence
│  (PostgreSQL)   │   (Redis)       │  • Redis: performance
│                 │                 │  • Connection pooling
└─────────────────┴─────────────────┘
```

### Technology Stack

- **Backend**: Rust (actix-web framework)
- **Database**: PostgreSQL 13+ (data persistence)
- **Cache**: Redis 6+ (performance & sessions)
- **Security**: JWT + bcrypt (authentication)
- **Container**: Docker (deployment)
- **Testing**: Automated test suite

## 🔧 Prerequisites

### System Requirements
- **Rust**: 1.70 or higher
- **PostgreSQL**: 13 or higher
- **Redis**: 6 or higher
- **Docker**: Optional (for containerized deployment)

**Why you need these:**
- **Rust** compiles and runs the service.
- **PostgreSQL** is the source of truth for user accounts and refresh tokens (permanent data).
- **Redis** keeps auth fast and safe under load (rate limiting + caching + blacklist).

### Install Dependencies

#### macOS (using Homebrew)
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install PostgreSQL
brew install postgresql
brew services start postgresql

# Install Redis
brew install redis
brew services start redis

# Verify installations
rustc --version
psql --version
redis-cli --version
```

#### Ubuntu/Debian
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# Install Redis
sudo apt install redis-server

# Start services
sudo systemctl start postgresql
sudo systemctl start redis-server

# Verify installations
rustc --version
psql --version
redis-cli --version
```

## ⚡ Quick Start

If you do only one section, do this one. It gets you from zero → running API.

### 1. Clone and Setup
```bash
# Clone the repository
git clone <repository-url>
cd universal-auth-service

# Copy environment configuration
cp configuration.yaml.example configuration.yaml
```

**What this does:** downloads the code and creates your local `configuration.yaml`.  
**Expected result:** you have a config file in the repo root that the service reads on startup.

### 2. Database Setup
```bash
# Create PostgreSQL database
createdb uas

# Run database migration
psql -U cesium -d uas -f database_migration.sql
```

**What this does:** creates the DB schema (tables + indexes) for users/tokens.  
**Expected result:** migration finishes without errors and tables like `users` and `refresh_tokens` exist.

### 3. Start Services
```bash
# Make sure PostgreSQL and Redis are running
brew services start postgresql  # macOS
brew services start redis       # macOS

# OR for Linux
sudo systemctl start postgresql
sudo systemctl start redis-server
```

**What this does:** starts your dependencies (PostgreSQL + Redis).  
**Expected result:** `psql` can connect and `redis-cli ping` returns `PONG`.

### 4. Run the Application
```bash
# Development mode
cargo run

# Production mode
cargo build --release
./target/release/uas
```

**What this does:** compiles and starts the HTTP server (default port 8000).  
**Expected result:** logs show successful connections to PostgreSQL + Redis and the server starts.

### 5. Test the API
```bash
# Health check
curl http://127.0.0.1:8000/api/v1/health

# Should return:
# {
#   "status": "Healthy",
#   "timestamp": "...",
#   "version": "0.1.0",
#   "uptime": 0,
#   "components": [...]
# }
```

**What this does:** verifies the whole stack works (HTTP + DB + Redis).  
**Expected result:** HTTP 200 with component statuses (database/redis) and response times.

## 📦 Installation

### Option 1: Local Development
```bash
# Clone repository
git clone <repository-url>
cd universal-auth-service

# Install dependencies
cargo build

# Run tests
cargo test

# Start development server
cargo run
```

### Option 2: Docker Deployment
```bash
# Build Docker image
docker build -t universal-auth-service .

# Run with Docker Compose
docker-compose up -d
```

### Option 3: Pre-built Binary
```bash
# Download latest release
wget https://github.com/your-org/universal-auth-service/releases/latest/download/uas-linux-x64.tar.gz

# Extract and run
tar -xzf uas-linux-x64.tar.gz
./uas
```

## ⚙️ Configuration

UAS reads configuration from **`configuration.yaml`** and uses env vars for runtime values.  
In production, prefer **environment variables for secrets** (e.g., `JWT_SECRET`, DB password).

### Environment Variables

Create a `.env` file in the project root:

```bash
# Database Configuration
DATABASE_URL=postgres://cesium:@127.0.0.1:5432/uas

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_ACCESS_EXPIRATION_HOURS=24
JWT_REFRESH_EXPIRATION_DAYS=30

# Application Configuration
RUST_LOG=info
APP_HOST=127.0.0.1
APP_PORT=8000
```

### Configuration File (`configuration.yaml`)

```yaml
application_host: "127.0.0.1"
application_port: 8000

database:
  host: "127.0.0.1"
  port: 5432
  username: "cesium"
  password: ""
  database_name: "uas"

redis:
  host: "127.0.0.1"
  port: 6379
  password: null
  database: null

jwt:
  secret: "your-super-secret-jwt-key-change-this-in-production"
  access_token_expiration_hours: 24
  refresh_token_expiration_days: 30
```

**How to think about these settings:**
- `database.*` must match your Postgres instance.
- `redis.*` must match your Redis instance.
- `jwt.secret` must be the **same across all UAS instances** behind a load balancer (otherwise tokens issued by one instance won’t validate on another).

### Security Notes

- **NEVER** commit JWT secrets to version control
- Use strong, randomly generated secrets in production
- Rotate JWT secrets periodically
- Use environment variables for sensitive configuration

## 🚀 Usage

### Starting the Service

```bash
# Development
cargo run

# Production
cargo build --release
./target/release/uas

# Docker
docker run -p 8000:8000 universal-auth-service
```

### Health Check

```bash
curl http://127.0.0.1:8000/api/v1/health
```

### Basic Authentication Flow

```bash
# 1. Register a new user
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "role": "user"
  }'

# 2. Verify email (use token from registration response)
curl http://127.0.0.1:8000/api/v1/auth/verify-email/YOUR_TOKEN_HERE

# 3. Login
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'

# 4. Use protected endpoints with JWT token
curl -X GET http://127.0.0.1:8000/api/v1/user/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**What’s happening in this flow (why it matters):**
- **Register** writes the user into Postgres and returns an email verification token (in real prod you would email it).
- **Verify email** flips `email_verified=true` so the account is allowed to log in.
- **Login** returns:
  - an **access token (JWT)** that your other microservices validate on every request
  - a **refresh token** used to get a new access token without re-entering credentials
- **Protected endpoints** require `Authorization: Bearer <access_token>`.

## 📚 API Documentation

### Base URL
```
http://127.0.0.1:8000/api/v1
```

### Authentication Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/auth/register` | ❌ | Register new user |
| GET | `/auth/verify-email/{token}` | ❌ | Verify email address |
| POST | `/auth/login` | ❌ | User login |
| POST | `/auth/refresh` | ❌ | Refresh access token |
| POST | `/auth/logout` | ✅ | User logout |
| POST | `/auth/password-reset` | ❌ | Request password reset |
| POST | `/auth/password-reset/confirm` | ❌ | Confirm password reset |

### User Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/user/profile` | ✅ | Get user profile |
| PUT | `/user/profile` | ✅ | Update user profile |
| POST | `/user/change-password` | ✅ | Change password |

### Admin Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/admin/users` | ✅ (Admin) | List all users |

### System Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/health` | ❌ | System health check |

### Complete API Documentation

📋 **Postman Collection**: Import `universal-auth-service.postman_collection.json`

**Tip:** run requests in order (register → verify → login → user endpoints). The collection stores tokens in variables automatically.

### Request/Response Examples

#### Registration Request
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "role": "user"
}
```

#### Login Response
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "uuid-here",
    "email": "john@example.com",
    "name": "John Doe",
    "role": "user",
    "email_verified": true,
    "created_at": "2024-01-30T10:00:00Z"
  },
  "expires_in": 86400
}
```

#### Error Response
```json
{
  "error": "InvalidCredentials",
  "message": "Invalid email or password"
}
```

## 🧪 Testing

### Automated Test Suite

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_user_registration

# Run with verbose output
cargo test -- --nocapture
```

### Manual Testing

Use the Postman collection or curl commands to test the API endpoints manually.

### Test Coverage

- ✅ Unit tests for all modules
- ✅ Integration tests for API endpoints
- ✅ Authentication flow testing
- ✅ Security testing (rate limiting, validation)
- ✅ Performance testing

### Load Testing

```bash
# Install hey (load testing tool)
go install github.com/rakyll/hey@latest

# Test health endpoint
hey -n 1000 -c 10 http://127.0.0.1:8000/api/v1/health

# Test authentication endpoint
hey -n 500 -c 5 -m POST \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}' \
  http://127.0.0.1:8000/api/v1/auth/login
```

## 🐳 Docker Deployment

### Docker Compose Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  uas:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgres://uas:password@postgres:5432/uas
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=your-jwt-secret-here
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=uas
      - POSTGRES_USER=uas
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./database_migration.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

volumes:
  postgres_data:
```

### Docker Commands

```bash
# Build and run
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f uas

# Stop services
docker-compose down

# Rebuild specific service
docker-compose up --build uas
```

## 🔒 Security

### Password Security
- **bcrypt hashing** with cost factor 12
- **Minimum password length** enforced (8 characters)
- **Password complexity** validation

### JWT Security
- **HS256 algorithm** for signing
- **Access tokens**: 24-hour expiration
- **Refresh tokens**: 30-day expiration
- **Token rotation** on refresh
- **Token blacklisting** on logout

### Rate Limiting
- **Login attempts**: 5 per 15 minutes per email
- **API calls**: Configurable per endpoint
- **Redis-backed** for distributed rate limiting

### Input Validation
- **SQL injection prevention** (parameterized queries)
- **XSS protection** (input sanitization)
- **CSRF protection** (JWT stateless design)
- **Request size limits** (configurable)

### Production Security Checklist

- [ ] **HTTPS only** (SSL/TLS certificates)
- [ ] **Secure JWT secrets** (environment variables)
- [ ] **Database encryption** (at rest)
- [ ] **Network security** (firewalls, VPC)
- [ ] **Regular security audits**
- [ ] **Dependency updates** (cargo audit)
- [ ] **Rate limiting** enabled
- [ ] **CORS properly configured**
- [ ] **Logging and monitoring** active

## 📊 Monitoring & Health Checks

### Health Check Endpoint

```bash
curl http://127.0.0.1:8000/api/v1/health
```

**Response:**
```json
{
  "status": "Healthy",
  "timestamp": "2024-01-30T10:00:00Z",
  "version": "0.1.0",
  "uptime": 3600,
  "components": [
    {
      "name": "database",
      "status": "Healthy",
      "response_time_ms": 5,
      "last_checked": "2024-01-30T10:00:00Z"
    },
    {
      "name": "redis",
      "status": "Healthy",
      "response_time_ms": 1,
      "last_checked": "2024-01-30T10:00:00Z"
    }
  ]
}
```

### Metrics to Monitor

- **Response Time**: API endpoint latency
- **Error Rate**: 5xx error percentage
- **Authentication Success**: Login success rate
- **Token Refresh Rate**: Refresh token usage
- **Database Connections**: Pool utilization
- **Redis Memory**: Cache memory usage
- **Rate Limiting**: Blocked requests

### Logging

```bash
# Enable debug logging
RUST_LOG=debug cargo run

# Production logging
RUST_LOG=info ./target/release/uas
```

## 🔧 Development

### Project Structure

```
universal-auth-service/
├── src/
│   ├── module/
│   │   ├── auth/
│   │   │   ├── model.rs      # Data structures
│   │   │   ├── repository.rs # Database operations
│   │   │   ├── cache.rs      # Redis operations
│   │   │   ├── service.rs    # Business logic
│   │   │   └── handler.rs    # HTTP handlers
│   │   └── health/          # Health monitoring
│   ├── routes/              # Route configuration
│   ├── configuration.rs     # App configuration
│   └── lib.rs              # Main application logic
├── database_migration.sql  # Database schema
├── universal-auth-service.postman_collection.json
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Multi-container setup
└── Cargo.toml           # Dependencies
```

### Development Workflow

```bash
# 1. Create feature branch
git checkout -b feature/new-auth-endpoint

# 2. Make changes
# Edit source files...

# 3. Run tests
cargo test

# 4. Check formatting
cargo fmt --check

# 5. Run linter
cargo clippy

# 6. Build and test manually
cargo run
# Test with Postman collection or curl commands

# 7. Commit changes
git add .
git commit -m "Add new authentication endpoint"

# 8. Create pull request
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Run security audit
cargo audit

# Generate documentation
cargo doc --open
```

### Adding New Features

1. **Database Changes**: Update `database_migration.sql`
2. **Models**: Add to `src/module/auth/model.rs`
3. **Repository**: Add database operations to `repository.rs`
4. **Cache**: Add Redis operations to `cache.rs`
5. **Service**: Add business logic to `service.rs`
6. **Handler**: Add HTTP endpoints to `handler.rs`
7. **Routes**: Register new routes in `routes/mod.rs`
8. **Tests**: Add tests for new functionality

## 🤝 Contributing

### Development Setup

1. **Fork the repository**
2. **Clone your fork**
   ```bash
   git clone https://github.com/your-username/universal-auth-service.git
   cd universal-auth-service
   ```

3. **Set up development environment**
   ```bash
   cargo build  # Build the project
   cargo test   # Run automated tests
   ```

4. **Create feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

5. **Make changes and test**
   ```bash
   cargo test
   # Test with Postman collection or curl commands
   ```

6. **Submit pull request**

### Guidelines

- **Code Style**: Follow Rust standards (`cargo fmt`, `cargo clippy`)
- **Tests**: Add tests for new features
- **Documentation**: Update README for API changes
- **Security**: Follow security best practices
- **Performance**: Consider performance implications

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style
- `refactor`: Code refactoring
- `test`: Testing
- `chore`: Maintenance

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Universal Auth Service

Permission is hereby granted, free of charge, to any person obtaining a copy
of this Software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

## 🆘 Troubleshooting

### Common Issues

#### PostgreSQL Connection Failed
```bash
# Check if PostgreSQL is running
ps aux | grep postgres

# Start PostgreSQL
brew services start postgresql  # macOS
sudo systemctl start postgresql # Linux

# Create database
createdb uas
```

#### Redis Connection Failed
```bash
# Check if Redis is running
redis-cli ping

# Start Redis
brew services start redis       # macOS
sudo systemctl start redis-server # Linux
```

#### Application Won't Start
```bash
# Check configuration
cat configuration.yaml

# Check environment variables
echo $DATABASE_URL
echo $JWT_SECRET

# Run with debug logging
RUST_LOG=debug cargo run
```

#### Tests Failing
```bash
# Clean and rebuild
cargo clean
cargo build

# Run specific test
cargo test test_name -- --nocapture

# Check database state
psql -d uas -c "SELECT * FROM users;"
```

### Performance Tuning

```bash
# Database connection pool
# Increase in configuration.yaml
database:
  max_connections: 20

# Redis memory optimization
# Configure Redis maxmemory in redis.conf
maxmemory 256mb
maxmemory-policy allkeys-lru
```

### Monitoring Queries

```sql
-- Active connections
SELECT count(*) FROM pg_stat_activity WHERE datname = 'uas';

-- Slow queries
SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;

-- Cache hit ratio
SELECT sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)) as cache_hit_ratio FROM pg_statio_user_tables;
```

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/universal-auth-service/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/universal-auth-service/discussions)
- **Documentation**: [Wiki](https://github.com/your-org/universal-auth-service/wiki)

## 🎯 Roadmap

### Version 1.1.0
- [ ] OAuth2 integration (Google, GitHub, etc.)
- [ ] Multi-factor authentication (2FA)
- [ ] Social login support
- [ ] Advanced rate limiting
- [ ] API key management

### Version 1.2.0
- [ ] Audit logging enhancements
- [ ] User activity tracking
- [ ] Advanced permissions system
- [ ] Service-to-service authentication
- [ ] Webhook support

### Version 2.0.0
- [ ] Microservices orchestration
- [ ] Distributed tracing
- [ ] Advanced analytics
- [ ] Machine learning integration

---

## 🚀 Ready for Production!

This Universal Auth Service is **enterprise-ready** and designed to handle authentication for modern applications. With its robust architecture, comprehensive security features, and scalable design, it's perfect for:

- ✅ **Microservices architectures**
- ✅ **High-traffic applications**
- ✅ **Enterprise environments**
- ✅ **API gateways**
- ✅ **Mobile applications**
- ✅ **Web applications**

**Start building secure, scalable applications today!** 🎉

---

*Built with ❤️ using Rust, PostgreSQL, and Redis*