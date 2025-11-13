# MediaStack Dashboard

A secure, centralized dashboard for managing *arr media services (Sonarr, Radarr, Lidarr, Prowlarr) and related automation tools with enterprise-grade authentication, real-time monitoring, and comprehensive service management.

![Security Rating](https://img.shields.io/badge/Security-⭐⭐⭐⭐⭐-brightgreen)
![Node](https://img.shields.io/badge/node-20.x-brightgreen)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue)
![Redis](https://img.shields.io/badge/Redis-7-red)

## 🚀 Current Status

**Default Credentials:**
- Username: `admin`
- Password: `Admin123!`

⚠️ **Change this immediately after first login!**

**Access:** https://arr.cirrolink.com (via Cloudflare Tunnel)

## ✨ Features

### 🔐 Authentication & Security
- JWT-based authentication with httpOnly cookies (24h expiration)
- Multi-user support with Role-Based Access Control (RBAC)
- 4 roles: Super Admin, Admin, User, Viewer
- bcryptjs password hashing (Alpine Linux compatible)
- CSRF protection for all state-changing operations
- Rate limiting on all endpoints
- Input validation and SQL injection prevention
- Force password change for default credentials

### 📊 Real-Time Dashboard
- Live service status monitoring (online/offline/activity)
- Server metrics: CPU, Memory, Uptime, Hostname
- Service activity tracking (downloads, queues, streams, indexers)
- Smart auto-refresh every 10 seconds (only updates on changes)
- Server metrics update every 30 seconds
- Flat GitHub-inspired dark theme

### 🛠️ Service Management
- Full CRUD operations with custom categories
- Support for 3 service types:
  - **External**: Direct links (e.g., https://plex.com)
  - **Proxied**: Nginx reverse proxy (e.g., /youtube → https://youtube.com)
  - **Internal**: Internal services
- Automatic nginx configuration for proxied services
- Real-time status and activity monitoring via API
- Path reuse from disabled/deleted services
- Custom icons and display ordering

### 📁 Category Management
- Create custom categories with icons and colors
- 10 icon options (film, download, chart, folder, server, music, book, globe, database, TV)
- 5 color options (blue, green, purple, orange, red)
- Display order customization
- Service assignment to categories

### 👥 User Management (Admin Only)
- Create, edit, deactivate users
- Password reset with optional force-change
- Role assignment with permission enforcement
- Activity tracking (last login, creation date)
- User profile management (display name, email)

### ⚙️ Settings
- Change display name
- Change password (requires current password verification)
- Profile management

## 🏗️ Tech Stack

### Backend
- **Runtime**: Node.js 20 (Alpine Linux)
- **Framework**: Express.js
- **Database**: PostgreSQL 16 (migrated from SQLite)
- **Cache**: Redis 7
- **Auth**: JWT + bcryptjs
- **Security**: Helmet, CSRF protection (csrf-csrf), rate limiting

### Frontend (Current - Vanilla JS)
- Vanilla JavaScript (ES6+)
- CSS3 with custom properties
- Flat design (no rounded corners, minimal animations)
- GitHub-inspired dark theme

### Frontend (Future - React Foundation)
- React 18 + TypeScript + Vite
- Tailwind CSS + Shadcn/ui
- React Query + React Router
- Foundation built in `/frontend` (incomplete)

### Infrastructure
- **Container**: dashboard-auth (node:20-alpine)
- **Database**: dashboard-postgres (postgres:16-alpine)
- **Cache**: dashboard-redis (redis:7-alpine)
- **Reverse Proxy**: nginx (arr-proxy container)
- **External Access**: Cloudflare Tunnel

## 📦 Project Structure

```
/opt/dashboard/
├── server.js                 # Express backend (2100+ lines)
├── package.json
├── .env                      # Environment variables (create from .env.example)
├── database/
│   ├── schema.sql           # PostgreSQL schema
│   ├── complete-schema.sql  # Full schema with all migrations
│   ├── migrations/          # Database migrations
│   │   └── 001_fix_service_path_unique_constraint.sql
│   └── migrate-sqlite-to-postgres.js
├── public/                  # Vanilla JS frontend
│   ├── login.html
│   ├── index.html           # Dashboard (requires auth)
│   ├── admin.html           # Service & Category management
│   ├── users.html           # User management (admin only)
│   ├── settings.html        # User settings
│   ├── css/
│   │   ├── variables.css    # Design system (colors, spacing)
│   │   ├── login.css
│   │   ├── dashboard.css
│   │   ├── admin.css
│   │   └── users.css
│   └── js/
│       ├── login.js
│       ├── dashboard.js     # Fallback hardcoded services
│       ├── admin.js         # Services & categories CRUD
│       ├── users.js         # User management CRUD
│       └── settings.js      # Profile & password management
├── frontend/                # React foundation (incomplete)
│   ├── src/
│   │   ├── api/            # API clients with CSRF handling
│   │   ├── contexts/       # Auth context
│   │   ├── types/          # TypeScript definitions
│   │   └── lib/            # Utilities
│   └── package.json
├── CLAUDE.md               # AI instructions
├── DEVELOPMENT.md          # Development guide
└── TROUBLESHOOTING.md      # Issues & solutions
```

## 🚀 Quick Start (Local Development)

### Prerequisites
- Node.js 20.x
- PostgreSQL 16
- Redis 7
- Docker (optional but recommended)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/mediastack-dashboard.git
cd mediastack-dashboard
```

2. **Install dependencies**
```bash
npm install
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Set up database**
```bash
# If using Docker:
docker-compose up -d dashboard-postgres dashboard-redis

# If using local PostgreSQL:
psql -U postgres -c "CREATE DATABASE dashboard;"
psql -U postgres -d dashboard < database/complete-schema.sql
```

5. **Start the server**
```bash
npm start
```

6. **Access the dashboard**
```
http://localhost:3000
```

See **DEVELOPMENT.md** for detailed setup instructions.

## 🔑 Environment Variables

Required variables in `.env`:

```bash
# JWT
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=dashboard
POSTGRES_USER=dashboard_app
POSTGRES_PASSWORD=your-secure-password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Service API Keys (optional, for status monitoring)
SONARR_API_KEY=your-sonarr-api-key
RADARR_API_KEY=your-radarr-api-key
PROWLARR_API_KEY=your-prowlarr-api-key
LIDARR_API_KEY=your-lidarr-api-key
TAUTULLI_API_KEY=your-tautulli-api-key

# CSRF (optional, auto-generated if not set)
CSRF_SECRET=your-csrf-secret
```

See `.env.example` for all variables.

## 📚 Documentation

- **[CLAUDE.md](CLAUDE.md)** - Instructions for Claude AI
- **[DEVELOPMENT.md](DEVELOPMENT.md)** - Development setup & workflow
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues & fixes

## 🐛 Known Issues & Fixes

All major issues have been resolved. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for:
- CSRF token validation fixes
- Category modal animation fixes
- Service path reuse fixes
- Session identifier mismatches
- And more...

## 🔒 Security Features

1. **Authentication**
   - JWT tokens in httpOnly cookies
   - CSRF protection via double-submit cookie pattern
   - Secure flag based on protocol (HTTP/HTTPS)

2. **Authorization**
   - Role-based access control (RBAC)
   - Permission-based endpoint protection
   - User can only manage users with lower privileges

3. **Password Security**
   - bcryptjs hashing (10 rounds, Alpine compatible)
   - Minimum 8 characters
   - Force change for default credentials
   - Current password required for changes

4. **API Security**
   - Rate limiting (100 req/min general, 5/15min for login)
   - Input validation and length limits
   - Parameterized SQL queries (no injection)
   - SSRF protection for URLs

5. **Headers**
   - Helmet.js security headers
   - HSTS, CSP, X-Frame-Options, etc.

## 📝 API Endpoints

See full API documentation in [DEVELOPMENT.md](DEVELOPMENT.md).

### Authentication
- `POST /api/login` - Login
- `POST /api/logout` - Logout
- `GET /api/verify` - Verify token

### Services
- `GET /api/services` - List services
- `POST /api/services` - Create service
- `PUT /api/services/:id` - Update service
- `DELETE /api/services/:id` - Delete service
- `GET /api/status` - Get status/activity

### Categories
- `GET /api/categories` - List categories
- `POST /api/categories` - Create category
- `PUT /api/categories/:id` - Update category
- `DELETE /api/categories/:id` - Delete category

### Users (Admin only)
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Deactivate user
- `PUT /api/users/:id/password` - Reset password

### System
- `GET /api/server-info` - Server metrics
- `GET /api/csrf-token` - Get CSRF token

## 🤝 Contributing

See [DEVELOPMENT.md](DEVELOPMENT.md) for contribution guidelines.

## 📄 License

Private project - All rights reserved.

## 🤖 AI-Assisted Development

This project was developed with assistance from Claude AI (Anthropic).

All commits include detailed messages documenting changes and rationale.

## 📧 Security Contact

For security issues: soufiane.hmiad@outlook.com

---

**Made with ❤️ by Soufiane Hmiad with Claude AI**
