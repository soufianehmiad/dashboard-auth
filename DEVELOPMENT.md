# Development Guide

Complete guide for setting up and developing MediaStack Dashboard locally.

## 🚀 Local Setup

###Prerequisites

- **Node.js**: 20.x
- **PostgreSQL**: 16.x
- **Redis**: 7.x
- **Git**: Latest
- **Docker** (optional but recommended)

### Initial Setup

1. **Clone Repository**
```bash
git clone https://github.com/YOUR_USERNAME/mediastack-dashboard.git
cd mediastack-dashboard
```

2. **Install Dependencies**
```bash
npm install
```

3. **Environment Configuration**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Database Setup**

**Option A: Using Docker (Recommended)**
```bash
# Start PostgreSQL and Redis
docker-compose up -d dashboard-postgres dashboard-redis

# Wait for containers to be ready
sleep 5

# Create schema
docker exec dashboard-postgres psql -U dashboard_app -d dashboard -f /path/to/database/complete-schema.sql
```

**Option B: Local Installation**
```bash
# Create database
psql -U postgres -c "CREATE DATABASE dashboard;"
psql -U postgres -c "CREATE USER dashboard_app WITH PASSWORD 'your-password';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE dashboard TO dashboard_app;"

# Load schema
psql -U dashboard_app -d dashboard < database/complete-schema.sql

# Start Redis
redis-server
```

5. **Start Development Server**
```bash
npm run dev
# Or
node server.js
```

6. **Access Application**
```
http://localhost:3000
```

## 📁 Project Structure Explained

```
/opt/dashboard/
├── server.js                    # Main Express application (2100+ lines)
│   ├── Security middleware (helmet, CSRF, rate limiting)
│   ├── Authentication (JWT, verifyToken)
│   ├── Authorization (RBAC, permissions)
│   ├── API endpoints
│   └── Error handling
│
├── database/
│   ├── schema.sql              # PostgreSQL table definitions
│   ├── complete-schema.sql     # Full schema with all migrations applied
│   ├── migrations/             # Database migrations
│   │   └── 001_fix_service_path_unique_constraint.sql
│   └── migrate-sqlite-to-postgres.js  # Migration script from SQLite
│
├── public/                     # Frontend files (vanilla JS)
│   ├── *.html                 # Page templates
│   ├── css/                   # Stylesheets
│   │   ├── variables.css      # Design system (colors, spacing, fonts)
│   │   ├── login.css
│   │   ├── dashboard.css
│   │   ├── admin.css
│   │   └── users.css
│   └── js/                    # Frontend logic
│       ├── login.js           # Login form handling
│       ├── dashboard.js       # Real-time dashboard updates
│       ├── admin.js           # Service & category CRUD
│       ├── users.js           # User management CRUD
│       └── settings.js        # Profile & password changes
│
└── frontend/                  # React foundation (incomplete)
    └── src/
        ├── api/              # API client modules
        ├── contexts/         # React contexts (Auth)
        ├── types/            # TypeScript definitions
        └── lib/              # Utilities
```

## 🔧 Development Workflow

### Making Changes

1. **Create Feature Branch**
```bash
git checkout -b feature/your-feature-name
```

2. **Make Changes**
   - Backend: Edit `server.js`
   - Frontend: Edit files in `public/`
   - Database: Create migration in `database/migrations/`

3. **Test Locally**
```bash
# Restart server
docker restart dashboard-auth

# Check logs
docker logs dashboard-auth --tail 50
```

4. **Commit Changes**
```bash
git add .
git commit -m "Description of changes

Detailed explanation of what was changed and why.

🤖 Generated with Claude Code

Co-Authored-By: Claude <noreply@anthropic.com>"
```

5. **Push to GitHub**
```bash
git push origin feature/your-feature-name
```

### Database Migrations

1. **Create Migration File**
```bash
# Create new migration in database/migrations/
# Format: 00X_description.sql
```

2. **Apply Migration**
```bash
docker exec dashboard-postgres psql -U dashboard_app -d dashboard -f /path/to/migration.sql

# Or locally:
psql -U dashboard_app -d dashboard < database/migrations/00X_description.sql
```

3. **Update complete-schema.sql**
```bash
# Export full schema after migration
docker exec dashboard-postgres pg_dump -U dashboard_app -d dashboard --schema-only > database/complete-schema.sql
```

## 🧪 Testing

### Manual Testing Checklist

**Authentication**
- [ ] Login with valid credentials
- [ ] Login with invalid credentials
- [ ] Logout
- [ ] Session persistence across page reloads
- [ ] Token expiration after 24h

**Dashboard**
- [ ] Service status updates
- [ ] Server metrics display
- [ ] Auto-refresh functionality
- [ ] Activity indicators

**Services Management**
- [ ] Create external service
- [ ] Create proxied service
- [ ] Edit service
- [ ] Delete service
- [ ] Assign to custom category

**Categories**
- [ ] Create category
- [ ] Edit category
- [ ] Delete category (should fail if services assigned)
- [ ] Custom icons and colors

**Users** (as Admin)
- [ ] Create user
- [ ] Edit user
- [ ] Reset password
- [ ] Deactivate user
- [ ] Assign roles

**Settings**
- [ ] Change display name
- [ ] Change password
- [ ] Invalid password rejection

### Browser Console Testing

Open DevTools (F12) and check for:
- No JavaScript errors
- Successful API calls (200/201 responses)
- Toast notifications on actions
- No CSRF token errors

## 🐛 Debugging

### Server Logs
```bash
# Real-time logs
docker logs dashboard-auth -f

# Last 100 lines
docker logs dashboard-auth --tail 100

# Since specific time
docker logs dashboard-auth --since 5m
```

### Database Queries
```bash
# Connect to database
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard

# Useful queries
SELECT * FROM users;
SELECT * FROM services WHERE enabled = true;
SELECT * FROM categories;
SELECT * FROM roles;
```

### Redis Cache
```bash
# Connect to Redis
docker exec -it dashboard-redis redis-cli

# View keys
KEYS *

# Get specific key
GET services:all

# Clear cache
FLUSHDB
```

## 📝 Code Style

### JavaScript
- Use ES6+ features
- Use async/await (not callbacks)
- Descriptive variable names
- Add comments for complex logic

### CSS
- Use CSS variables for colors/spacing (defined in `variables.css`)
- Flat design (no border-radius, minimal animations)
- Mobile-first responsive design

### Commits
- Clear, descriptive messages
- Include "why" not just "what"
- Reference issue numbers if applicable

## 🔐 Security Checklist

Before pushing code:

- [ ] No hardcoded secrets/passwords
- [ ] Environment variables used for sensitive data
- [ ] Input validation on all user inputs
- [ ] SQL queries use parameterized statements
- [ ] CSRF tokens required for state-changing operations
- [ ] Proper error handling (no stack traces to client)
- [ ] Rate limiting on endpoints

## 🚢 Deployment

### Production Checklist

1. **Environment Variables**
   - [ ] Strong `JWT_SECRET`
   - [ ] Strong database passwords
   - [ ] Valid `CSRF_SECRET`
   - [ ] All service API keys configured

2. **Security**
   - [ ] Change default admin password
   - [ ] HTTPS enabled
   - [ ] Secure cookies enabled
   - [ ] Rate limiting configured

3. **Database**
   - [ ] Backup strategy in place
   - [ ] Connection pooling configured
   - [ ] Proper indexes created

4. **Monitoring**
   - [ ] Log aggregation setup
   - [ ] Error tracking
   - [ ] Uptime monitoring

### Docker Deployment
```bash
# Build image
docker build -t mediastack-dashboard .

# Run container
docker run -d \
  --name dashboard-auth \
  -p 3000:3000 \
  -e JWT_SECRET=your-secret \
  -v $(pwd)/data:/app/data \
  --network arr-network \
  mediastack-dashboard
```

## 🆘 Getting Help

1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. Review git commit history for context
3. Check server logs for errors
4. Consult [CLAUDE.md](CLAUDE.md) for AI assistance guidelines

## 📚 Useful Commands

```bash
# Docker
docker ps                              # List containers
docker restart dashboard-auth          # Restart app
docker logs dashboard-auth -f         # Follow logs
docker exec -it dashboard-auth sh     # Shell into container

# Database
docker exec dashboard-postgres pg_dump -U dashboard_app dashboard > backup.sql
docker exec -i dashboard-postgres psql -U dashboard_app dashboard < backup.sql

# Git
git log --oneline --graph            # View commit history
git diff HEAD~1                       # View last commit changes
git show <commit-hash>                # View specific commit

# NPM
npm outdated                          # Check for updates
npm audit                             # Security audit
npm ci                                # Clean install from package-lock
```

## 🏗️ Future Development

### Planned Features
- [ ] Complete React frontend (foundation exists in `/frontend`)
- [ ] WebSocket support for real-time updates
- [ ] Advanced service filters and search
- [ ] Bulk operations
- [ ] Service health history/graphs
- [ ] Email notifications
- [ ] Two-factor authentication
- [ ] API rate limiting per user
- [ ] Audit logging

### React Frontend Continuation

The React foundation is 30% complete. To continue:

1. Install dependencies:
```bash
cd frontend
npm install
```

2. Start development:
```bash
npm run dev
```

3. Complete remaining:
   - UI components (Button, Input, Modal, Table, etc.)
   - Page components
   - React Router setup
   - React Query hooks
   - Integration with backend

See `/frontend/src/api/` for complete API client implementations.
