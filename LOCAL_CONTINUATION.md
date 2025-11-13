# MediaStack Dashboard - Local Development Continuation

## Current Situation

I'm working on **MediaStack Dashboard**, a secure dashboard for managing *arr media services. The project was developed on a **remote production server** (`arr.cirrolink.com`) and I've now **cloned it locally** to my Mac for development.

**Repository:** https://github.com/soufianehmiad/dashboard-auth
**Local Path:** `~/WebstormProjects/dashboard-auth`
**Current Branch:** `main`

## What's Been Done

### ✅ Completed on Remote Server
- Full-featured dashboard with JWT authentication, RBAC, PostgreSQL, Redis
- User management, service management, category management
- Real-time status monitoring for *arr services
- All frontend UX improvements (animations, toasts, modals)
- Comprehensive documentation (README.md, DEVELOPMENT.md, TROUBLESHOOTING.md)
- All bugs fixed (CSRF validation, category assignment, path reuse, etc.)

### ✅ Completed on Local Mac
- Cloned repository from GitHub
- Docker Desktop is running
- Docker Compose files updated for local development (removed production network dependencies)
- Started PostgreSQL container: `dashboard-postgres` (running on port 5432)
- Started Redis container: `dashboard-redis` (running on port 6379)
- Created `.env` file with all API keys from production server

## Current Problem

**PostgreSQL database is empty** - the initialization script didn't run when the container started.

When I run:
```bash
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard
\dt
```

Result: `Did not find any relations.` (no tables)

## What I Need

**Immediate Task:** Get the PostgreSQL database initialized with the complete schema so I can run the application locally.

The schema file is at: `~/WebstormProjects/dashboard-auth/database/complete-schema.sql`

## My Environment

**Local Machine:** MacBook Pro (macOS)
**Docker:** Docker Desktop v28.5.2
**Docker Compose:** v2.40.3
**Node.js:** Installed
**IDE:** WebStorm (JetBrains)

**Containers Running:**
```bash
$ docker ps
CONTAINER ID   IMAGE                COMMAND                  CREATED         STATUS         PORTS                    NAMES
xxxxx          redis:7-alpine       "docker-entrypoint.s…"   X minutes ago   Up X minutes   0.0.0.0:6379->6379/tcp   dashboard-redis
xxxxx          postgres:16-alpine   "docker-entrypoint.s…"   X minutes ago   Up X minutes   0.0.0.0:5432->5432/tcp   dashboard-postgres
```

## My .env File (Already Created)

```env
# JWT Authentication
JWT_SECRET=GEOoO8scjdmi48LKkjf+jaPlv4J0aTK+xRc65ohgGdQ=

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=dashboard
POSTGRES_USER=dashboard_app
POSTGRES_PASSWORD=ynrLPwRFqMPtvtwdaMbir+NsjQnId88JczeoHXc+uvE=

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=local-dev-redis-password

# Application
NODE_ENV=development
PORT=3000

# *arr Services API Keys (from production server)
SONARR_API_KEY=67f5f8a7c42e45e4a85666243bdf3475
SONARR_ANIME_API_KEY=b943e8761f4745cea4f867fad56a7b51
RADARR_API_KEY=9088e197d8ac4aeeb002d944d27594c8
LIDARR_API_KEY=23b4503c712d4cb685c90b718ea066ce
PROWLARR_API_KEY=b1161ec893bf4165b4f8140f2b0e42e6
SABNZBD_API_KEY=42705c2605d249e6ab1eb9c7577ccb72
TAUTULLI_API_KEY=3c63da3a9e15460fa49e473322ff3270
```

## Important Context

### 1. Tech Stack
- **Backend:** Node.js 20 + Express.js
- **Database:** PostgreSQL 16 (migrated from SQLite)
- **Cache:** Redis 7
- **Frontend:** Vanilla JavaScript (React foundation exists in `/frontend` but incomplete)
- **Auth:** JWT + bcryptjs (NOT bcrypt - Alpine Linux compatibility)
- **Security:** Helmet, CSRF (csrf-csrf), rate limiting
- **Container Base:** node:20-alpine

### 2. Default Credentials
- **Username:** `admin`
- **Password:** `Admin123!`

### 3. Database Schema
**Location:** `database/complete-schema.sql`

**Includes:**
- Tables: users, services, categories, roles, user_roles, audit_logs, api_keys
- Default admin user with bcryptjs hash
- Initial categories (contentManagement, downloadClients, managementAnalytics)
- Initial roles (super_admin, admin, power_user, user, read_only)
- All migrations applied (including path unique constraint fix)
- Indexes and foreign key constraints

### 4. Services Location
The *arr services (Sonarr, Radarr, Lidarr, Prowlarr, qBittorrent, SABnzbd, Tautulli) are running on the **remote production server** at `arr.cirrolink.com`, NOT locally.

For local development:
- **Service status checks will fail** unless SSH tunnels are set up
- **Authentication and user management will work** without remote services
- **Service CRUD operations will work** (stored in local database)

### 5. Design System
- **Flat design:** No border-radius, minimal shadows
- **GitHub-inspired dark theme**
- **Color palette:** Defined in `public/css/variables.css`
- **Toast notifications:** Custom implementation (not library)
- **Modal animations:** CSS keyframes with cubic-bezier easing

## Project Structure

```
~/WebstormProjects/dashboard-auth/
├── server.js                    # Main Express app (2100+ lines)
├── package.json                 # Dependencies
├── .env                         # Environment variables (created)
├── database/
│   ├── complete-schema.sql      # Full schema with migrations
│   ├── schema.sql               # Original schema
│   └── migrations/              # Database migrations
│       └── 001_fix_service_path_unique_constraint.sql
├── public/                      # Frontend (vanilla JS)
│   ├── login.html
│   ├── index.html               # Dashboard
│   ├── admin.html               # Service & category management
│   ├── users.html               # User management
│   ├── settings.html            # User settings
│   ├── css/                     # Stylesheets
│   │   ├── variables.css        # Design system
│   │   ├── dashboard.css
│   │   ├── admin.css
│   │   └── users.css
│   └── js/                      # Frontend logic
│       ├── dashboard.js
│       ├── admin.js
│       ├── users.js
│       └── settings.js
├── frontend/                    # React foundation (incomplete - 30% done)
│   ├── src/
│   │   ├── api/                 # API clients
│   │   ├── contexts/            # React contexts
│   │   └── types/               # TypeScript types
│   └── package.json
├── docker-compose.postgres.yml  # PostgreSQL container config
├── docker-compose.redis.yml     # Redis container config
├── README.md                    # Project overview
├── DEVELOPMENT.md               # Development guide
├── TROUBLESHOOTING.md           # Solutions to common issues
└── CLAUDE.md                    # AI assistance guidelines
```

## Next Steps Needed

1. **Fix PostgreSQL initialization** - Import `database/complete-schema.sql` into the empty database
2. **Verify database has tables and admin user**
3. **Install dependencies:** `npm install`
4. **Start Node.js application:** `npm start`
5. **Test login at:** `http://localhost:3000`
6. **(Optional) Set up SSH tunnels** if testing service status monitoring

## Reference Documentation

All documentation is in the repository:
- **DEVELOPMENT.md** - Complete development setup guide with testing checklists
- **TROUBLESHOOTING.md** - Solutions to 15+ issues encountered during development
- **CLAUDE.md** - Architecture, design system, implementation details (for AI assistance)
- **README.md** - Project overview, features, quick start

## Key Issues Previously Solved

### CSRF Token Validation (3 iterations)
- **Iteration 1:** Wrong option name (`getTokenFromRequest` vs `getCsrfTokenFromRequest`)
- **Iteration 2:** Explicit override caused initialization errors
- **Iteration 3:** Session identifier mismatch - fixed by using JWT cookie value
- **Solution:** `getSessionIdentifier: (req) => req.cookies.token || 'anonymous'`

### Category Assignment (400 error)
- **Problem:** Hardcoded category validation instead of database lookup
- **Solution:** Changed to database validation in POST/PUT service endpoints

### Path Reuse (409 error)
- **Problem:** Global unique constraint on `path` column
- **Solution:** Partial unique index `WHERE enabled = true`
- **Migration:** `database/migrations/001_fix_service_path_unique_constraint.sql`

### UI Feedback (buttons lead to nothing)
- **Problem:** Used old `showGlobalMessage()` instead of toast notifications
- **Solution:** Updated all CRUD functions to use `showSuccess()` and `showError()`

### Modal Animations
- **Problem:** Using `style.display` instead of CSS classes
- **Solution:** Use `classList.add/remove('show')` for CSS animations

## Production Server Info (for reference)

**URL:** https://arr.cirrolink.com
**Container:** `dashboard-auth`
**Network:** `arr-proxy_arr-network`
**IP:** 172.19.0.3
**Port:** 3000 (internal)
**Reverse Proxy:** nginx (arr-proxy container)
**External Access:** Cloudflare Tunnel

## Git Commands for Reference

```bash
# Pull latest changes
git pull origin main

# Check status
git status

# View recent commits
git log --oneline --graph -10

# View specific commit
git show <commit-hash>
```

## Useful Commands

### Docker
```bash
# View logs
docker logs dashboard-postgres --tail 50
docker logs dashboard-redis --tail 50

# Connect to PostgreSQL
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard

# Connect to Redis
docker exec -it dashboard-redis redis-cli -a local-dev-redis-password

# Restart containers
docker restart dashboard-postgres dashboard-redis

# Stop and remove (preserves volumes)
docker compose -f docker-compose.postgres.yml down
docker compose -f docker-compose.redis.yml down

# Remove volumes (fresh start)
docker volume rm dashboard-auth_postgres_data dashboard-auth_redis_data
```

### PostgreSQL
```sql
-- List tables
\dt

-- Check users
SELECT id, username, display_name, role FROM users;

-- Check services
SELECT id, name, path, enabled FROM services;

-- Check categories
SELECT id, name, display_order FROM categories;

-- Exit
\q
```

### Node.js
```bash
# Install dependencies
npm install

# Start development server
npm start

# Check for outdated packages
npm outdated

# Security audit
npm audit
```

## Expected Outcome

After fixing the PostgreSQL initialization:

1. **Database has all tables:**
   - users, services, categories, roles, user_roles, audit_logs, api_keys

2. **Admin user exists:**
   - Username: `admin`
   - Password: `Admin123!` (bcryptjs hash in database)

3. **Application starts successfully:**
   ```
   ✓ Connected to Redis
   ✓ Connected to PostgreSQL
   🚀 Server running on port 3000
   ```

4. **Can log in at:** `http://localhost:3000`

5. **Dashboard shows:**
   - Empty service list (services from production not in local DB yet)
   - Working navigation (Dashboard, Settings, Manage Services, Users, Logout)
   - Full CRUD operations for services, categories, users

## Question for Claude

**Please help me initialize the PostgreSQL database with the complete schema so I can start developing locally.**

The schema file exists at `~/WebstormProjects/dashboard-auth/database/complete-schema.sql` but the PostgreSQL container didn't run it during initialization. I need to manually import it or troubleshoot why the initialization script didn't run.
