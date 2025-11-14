# MediaStack Dashboard - Project Audit Prompt

## Purpose

This audit validates that MediaStack Dashboard meets all project requirements, follows best practices, and is production-ready.

## How to Use This Audit

**For AI Assistant (Claude):**
```
Please conduct a comprehensive audit of the MediaStack Dashboard project.
Read AUDIT_PROMPT.md and verify each requirement.
For each section, check the code, test the functionality, and report:
✅ PASS - with evidence
❌ FAIL - with specific issues
⚠️  PARTIAL - with what's missing
```

**For Manual Review:**
Use this as a checklist, testing each item and documenting results.

---

## 1. Core Functionality Requirements

### 1.1 Authentication System
**Requirements:**
- [ ] JWT-based authentication with httpOnly cookies
- [ ] 24-hour token expiration
- [ ] Secure cookie configuration (httpOnly, sameSite, dynamic secure flag)
- [ ] bcryptjs password hashing (10 rounds, Alpine-compatible)
- [ ] Login endpoint with proper validation
- [ ] Logout endpoint that clears cookies
- [ ] Token verification middleware on protected routes
- [ ] Automatic redirect to login on invalid/expired tokens
- [ ] Return path preservation after login

**Verification Steps:**
```bash
# Test login
curl -c cookies.txt -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!"}'

# Test protected route with token
curl -b cookies.txt http://localhost:3000/api/verify

# Test logout
curl -b cookies.txt -X POST http://localhost:3000/api/logout

# Test expired token behavior (wait 24h or manually test)
```

**Code Locations:**
- Server.js lines ~250-350 (login endpoint)
- Server.js lines ~150-200 (verifyToken middleware)
- Cookie configuration in login response

---

### 1.2 Role-Based Access Control (RBAC)
**Requirements:**
- [ ] 4 distinct roles: Super Admin, Admin, User, Viewer
- [ ] Roles stored in database with permissions
- [ ] Role-based middleware (requireRole, requirePermission)
- [ ] Permission enforcement on sensitive endpoints
- [ ] User cannot manage users with equal/higher privileges
- [ ] Role assignment restricted to admins
- [ ] Proper error messages for unauthorized access

**Verification Steps:**
```bash
# Check roles table
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT * FROM roles ORDER BY level DESC;"

# Check user roles
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT u.username, r.name as role, r.permissions
      FROM users u
      JOIN user_roles ur ON u.id = ur.user_id
      JOIN roles r ON ur.role_id = r.id;"

# Test permission enforcement
# Try to create admin user as regular user (should fail)
# Try to delete higher-privilege user (should fail)
```

**Code Locations:**
- Server.js ~200-250 (RBAC middleware)
- Database schema: roles, user_roles tables
- User management endpoints (~1800-2000)

---

### 1.3 User Management
**Requirements:**
- [ ] Create user with username, password, role, display name, email
- [ ] Update user (display name, email, role, active status)
- [ ] Deactivate user (soft delete via is_active flag)
- [ ] Reset user password with optional force-change flag
- [ ] List all users with role information
- [ ] Password validation (minimum 8 characters)
- [ ] Force password change for default credentials
- [ ] Admin-only access to user management
- [ ] Track last login, creation date, created_by

**Verification Steps:**
1. Log in as admin
2. Go to /users page
3. Create new user with each role
4. Edit user details
5. Reset password with force-change enabled
6. Deactivate user
7. Verify deactivated user cannot login
8. Check audit trail in database

**Code Locations:**
- Server.js ~1800-2100 (user management endpoints)
- public/users.html (UI)
- public/js/users.js (frontend logic)

---

### 1.4 Service Management
**Requirements:**
- [ ] Create, read, update, delete (CRUD) services
- [ ] Service types: External, Proxied, Internal
- [ ] Fields: name, path, icon_url, category, api_url, api_key_env, display_order
- [ ] Path uniqueness only for enabled services (partial unique index)
- [ ] Soft delete (enabled flag)
- [ ] Path reuse from disabled services
- [ ] Category assignment (database validation, not hardcoded)
- [ ] Display order customization
- [ ] Icon URL validation
- [ ] Service status monitoring via API

**Verification Steps:**
```bash
# Check partial unique index exists
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "\d services"
# Should show: services_path_enabled_unique (path) WHERE enabled = true

# Test path reuse
# 1. Create service with path /test
# 2. Disable service
# 3. Create new service with path /test (should succeed)

# Test category validation
# 1. Create custom category
# 2. Assign to service (should succeed)
# 3. Try invalid category ID (should fail with 400)
```

**Code Locations:**
- Server.js ~1500-1800 (service endpoints)
- database/migrations/001_fix_service_path_unique_constraint.sql
- public/admin.html, public/js/admin.js

---

### 1.5 Category Management
**Requirements:**
- [ ] Create custom categories with name, icon, color, display_order
- [ ] Update category details
- [ ] Delete category (only if no services assigned)
- [ ] 10 icon options: film, download, chart, folder, server, music, book, globe, database, tv
- [ ] 5 color options: blue, green, purple, orange, red
- [ ] Display order customization
- [ ] Foreign key constraint prevents deletion with assigned services
- [ ] Default categories: contentManagement, downloadClients, managementAnalytics

**Verification Steps:**
1. Go to /admin page
2. Click "Manage Categories"
3. Create new category with custom icon/color
4. Assign services to category
5. Try to delete category with services (should fail)
6. Reassign services, then delete category (should succeed)

**Code Locations:**
- Server.js ~1300-1500 (category endpoints)
- public/admin.html (category modal)
- Database schema: categories table with foreign keys

---

### 1.6 Real-Time Dashboard
**Requirements:**
- [ ] Server metrics: hostname, uptime, CPU, memory
- [ ] Service status: online/offline/activity
- [ ] Service activity tracking (queue counts, downloads, streams, indexers)
- [ ] Smart auto-refresh (10s for services, 30s for metrics)
- [ ] Change detection (only update UI when data changes)
- [ ] Activity indicators (green for active, gray for idle)
- [ ] Comprehensive metrics bar (7 metrics)
- [ ] Last update timestamp
- [ ] Service cards organized by category
- [ ] Fallback to hardcoded services if API fails

**Verification Steps:**
1. Open dashboard at /
2. Check server metrics update every 30s
3. Check service status updates every 10s
4. Verify activity indicators show correctly
5. Check browser console for errors
6. Disconnect from API, verify fallback works

**Code Locations:**
- Server.js ~900-1200 (status endpoints, activity logic)
- public/js/dashboard.js (auto-refresh, change detection)
- public/index.html (metrics bar)

---

### 1.7 Settings & Profile Management
**Requirements:**
- [ ] Change display name
- [ ] Change password (requires current password)
- [ ] Password confirmation
- [ ] Display name shown in navbar
- [ ] Username immutable (login identifier)
- [ ] Validation: minimum 8 characters for new password
- [ ] Toast notifications for success/error
- [ ] No forced logout after password change

**Verification Steps:**
1. Go to /settings
2. Change display name → verify navbar updates
3. Change password with wrong current password → should fail
4. Change password correctly → should succeed
5. Logout and login with new password
6. Verify still logged in after password change

**Code Locations:**
- Server.js ~1100-1300 (profile endpoints)
- public/settings.html, public/js/settings.js

---

## 2. Security Requirements

### 2.1 CSRF Protection
**Requirements:**
- [ ] Double-submit cookie pattern implementation
- [ ] csrf-csrf library configured correctly
- [ ] CSRF token endpoint (/api/csrf-token)
- [ ] Token validation on POST/PUT/DELETE operations
- [ ] Proper session identifier (JWT cookie value)
- [ ] Frontend includes x-csrf-token header
- [ ] No CSRF on GET/HEAD/OPTIONS requests

**Verification Steps:**
```bash
# Test CSRF protection
# 1. Get CSRF token
curl -c cookies.txt http://localhost:3000/api/csrf-token

# 2. Try POST without token (should fail)
curl -b cookies.txt -X POST http://localhost:3000/api/services \
  -H "Content-Type: application/json" \
  -d '{"name":"Test"}'

# 3. Try POST with token (should succeed after login)
curl -b cookies.txt -X POST http://localhost:3000/api/services \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: TOKEN_HERE" \
  -d '{"name":"Test","path":"/test",...}'
```

**Code Locations:**
- Server.js ~685-701 (CSRF configuration)
- Server.js ~750 (CSRF token endpoint)
- All frontend JS files (CSRF header in fetch requests)

**Critical Check:**
```javascript
// Verify session identifier uses JWT cookie:
getSessionIdentifier: (req) => {
  return req.cookies.token || 'anonymous';
}
```

---

### 2.2 Password Security
**Requirements:**
- [ ] bcryptjs (not bcrypt) for Alpine compatibility
- [ ] 10 salt rounds
- [ ] Minimum 8 characters
- [ ] Current password required for changes
- [ ] Force change for default credentials (admin/Admin123!)
- [ ] Password hashes never exposed in API
- [ ] Failed login attempt tracking (database field exists)
- [ ] Account lockout capability (locked_until field exists)

**Verification Steps:**
```bash
# Check password hashing
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT username, password, password_must_change FROM users WHERE username='admin';"
# Password should be bcryptjs hash (starts with $2a$ or $2b$)

# Test force change
# 1. Login with default password
# 2. Should be prompted to change password (if implemented)

# Test password requirements
# Try to set password < 8 chars (should fail)
```

**Code Locations:**
- Server.js line 3 (require bcryptjs)
- Server.js login endpoint (bcrypt.compare)
- Server.js password change endpoint (bcrypt.hash)

---

### 2.3 Input Validation & SQL Injection Prevention
**Requirements:**
- [ ] All SQL queries use parameterized statements ($1, $2, etc.)
- [ ] No string concatenation in SQL queries
- [ ] Input length limits enforced
- [ ] Email validation (if required)
- [ ] URL validation for service URLs
- [ ] No user input directly in SQL
- [ ] Proper error handling (no stack traces to client)

**Verification Steps:**
```bash
# Code review: Search for SQL injection vulnerabilities
grep -n "pool.query.*+" server.js
# Should return NO results (no string concatenation)

grep -n "pool.query.*\$[0-9]" server.js
# Should return MANY results (parameterized queries)

# Test SQL injection attempts
# Try username: admin' OR '1'='1
# Try service name with SQL: '; DROP TABLE users; --
# All should be safely escaped
```

**Code Locations:**
- All database queries in server.js
- Input validation in endpoints

---

### 2.4 Rate Limiting
**Requirements:**
- [ ] General rate limit: 100 requests/15 minutes
- [ ] Login rate limit: 5 attempts/15 minutes
- [ ] Redis-backed rate limiting (persistent)
- [ ] Rate limit headers in response
- [ ] Proper error messages when rate limited
- [ ] IP-based limiting

**Verification Steps:**
```bash
# Test login rate limiting
for i in {1..6}; do
  curl -X POST http://localhost:3000/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}'
  echo "Attempt $i"
done
# 6th attempt should return 429 Too Many Requests

# Check rate limit headers
curl -I http://localhost:3000/api/status
# Should see: X-RateLimit-Limit, X-RateLimit-Remaining
```

**Code Locations:**
- Server.js ~100-150 (rate limiting configuration)
- Server.js login endpoint (stricter rate limit)

---

### 2.5 Security Headers (Helmet.js)
**Requirements:**
- [ ] Helmet.js configured and active
- [ ] HSTS enabled (Strict-Transport-Security)
- [ ] Content Security Policy (CSP)
- [ ] X-Frame-Options: DENY
- [ ] X-Content-Type-Options: nosniff
- [ ] Referrer-Policy configured
- [ ] No X-Powered-By header (Express signature hidden)

**Verification Steps:**
```bash
# Check security headers
curl -I http://localhost:3000/

# Should include:
# Strict-Transport-Security: max-age=...
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# Referrer-Policy: no-referrer
# Content-Security-Policy: ...

# Should NOT include:
# X-Powered-By: Express
```

**Code Locations:**
- Server.js ~50-80 (Helmet configuration)

---

## 3. Database Requirements

### 3.1 Schema Completeness
**Requirements:**
- [ ] Users table with all security fields
- [ ] Services table with soft delete
- [ ] Categories table with customization
- [ ] Roles table with permissions
- [ ] User_roles junction table
- [ ] Audit_logs table for tracking
- [ ] Api_keys table for future use
- [ ] All foreign keys properly defined
- [ ] All indexes created for performance
- [ ] Default admin user exists

**Verification Steps:**
```bash
# Check all tables exist
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard -c "\dt"

# Check foreign keys
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard -c "\d services"
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard -c "\d user_roles"

# Check indexes
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard -c "\di"

# Check admin user
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT username, role FROM users WHERE username='admin';"
```

**Code Locations:**
- database/complete-schema.sql (full schema)
- database/schema.sql (original)

---

### 3.2 Migrations
**Requirements:**
- [ ] Migration directory exists (database/migrations/)
- [ ] Migration 001: Path unique constraint fix
- [ ] Migrations documented with comments
- [ ] Migration naming convention: NNN_description.sql
- [ ] All migrations applied to complete-schema.sql

**Verification Steps:**
```bash
# Check migration files exist
ls -la database/migrations/

# Verify partial unique index exists
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT indexname, indexdef FROM pg_indexes WHERE tablename='services';"
# Should show: services_path_enabled_unique with WHERE enabled = true
```

**Code Locations:**
- database/migrations/001_fix_service_path_unique_constraint.sql

---

### 3.3 Data Integrity
**Requirements:**
- [ ] No orphaned records (all foreign keys valid)
- [ ] Cascading deletes configured where appropriate
- [ ] Check constraints for valid values (e.g., role names)
- [ ] NOT NULL constraints on required fields
- [ ] Unique constraints where needed
- [ ] Default values set appropriately

**Verification Steps:**
```bash
# Check for orphaned services (invalid category)
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT s.id, s.name, s.category_id
      FROM services s
      LEFT JOIN categories c ON s.category_id = c.id
      WHERE c.id IS NULL;"
# Should return 0 rows

# Check constraints
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "\d+ users"
# Should show check constraint for valid_role
```

---

## 4. Frontend Requirements

### 4.1 User Interface Quality
**Requirements:**
- [ ] Flat design (no border-radius)
- [ ] GitHub-inspired dark theme
- [ ] Consistent color palette (CSS variables)
- [ ] Toast notifications for all actions
- [ ] Modal animations (fade-in, scale)
- [ ] Button hover/active states
- [ ] Form focus indicators
- [ ] Loading states/spinners
- [ ] Responsive layout (mobile-friendly)
- [ ] No console errors in browser

**Verification Steps:**
1. Open each page (/login, /, /admin, /users, /settings)
2. Check DevTools console (F12) for errors
3. Test all interactive elements
4. Verify toast notifications appear
5. Check modal animations smooth
6. Test on mobile viewport (responsive)
7. Verify colors match design system

**Code Locations:**
- public/css/variables.css (design system)
- All CSS files use var(--color-*)
- Toast system in users.css, admin.css

---

### 4.2 Navigation & UX
**Requirements:**
- [ ] Fixed navbar (60px height) across all pages
- [ ] User menu dropdown with display name
- [ ] Dropdown items: Settings, Manage Services, Users (if admin), Logout
- [ ] Active page indication
- [ ] Logout button red on hover
- [ ] Normal footer (not fixed/sticky)
- [ ] Breadcrumb or page title
- [ ] Consistent spacing/padding

**Verification Steps:**
1. Measure navbar height (should be 60px)
2. Check user menu shows display name
3. Test dropdown opens/closes smoothly
4. Verify non-admin users don't see "Users" link
5. Check footer at bottom (not floating)

**Code Locations:**
- All HTML files (shared navbar)
- CSS: header height: 60px

---

### 4.3 Form Validation
**Requirements:**
- [ ] Client-side validation before submit
- [ ] Required field indicators
- [ ] Password confirmation matching
- [ ] Email format validation
- [ ] URL format validation
- [ ] Minimum length enforcement
- [ ] Clear error messages
- [ ] Prevent double-submission

**Verification Steps:**
1. Try to submit forms with empty required fields
2. Try mismatched password confirmation
3. Try invalid email format
4. Try URL without protocol
5. Try password < 8 characters
6. Verify error messages clear and helpful

**Code Locations:**
- All frontend JS files (validation functions)
- HTML form attributes (required, type, minlength)

---

## 5. Documentation Requirements

### 5.1 README.md
**Requirements:**
- [ ] Project overview and description
- [ ] Features list (comprehensive)
- [ ] Tech stack details
- [ ] Security features highlighted
- [ ] Quick start guide
- [ ] Environment variables documentation
- [ ] API endpoints overview
- [ ] Default credentials warning
- [ ] Project structure
- [ ] License information
- [ ] Contact information

**Verification:**
Read README.md and verify all sections present and accurate.

---

### 5.2 DEVELOPMENT.md
**Requirements:**
- [ ] Prerequisites (Node.js, PostgreSQL, Redis, Docker)
- [ ] Initial setup steps (clone, install, configure)
- [ ] Database setup (Docker and local)
- [ ] Development workflow
- [ ] Database migration process
- [ ] Manual testing checklist
- [ ] Debugging commands
- [ ] Code style guidelines
- [ ] Security checklist
- [ ] Deployment checklist
- [ ] Future development roadmap

**Verification:**
Follow DEVELOPMENT.md setup steps on clean machine - should work end-to-end.

---

### 5.3 TROUBLESHOOTING.md
**Requirements:**
- [ ] Common issues with solutions
- [ ] CSRF token errors (all 3 iterations documented)
- [ ] Category assignment errors
- [ ] Path reuse errors
- [ ] UI feedback issues
- [ ] Database initialization issues
- [ ] Docker container issues
- [ ] Icon/display issues
- [ ] Password/security issues
- [ ] General debugging commands

**Verification:**
Check that all major issues encountered during development are documented.

---

### 5.4 CLAUDE.md
**Requirements:**
- [ ] Project overview for AI assistance
- [ ] Architecture explanation
- [ ] Tech stack details
- [ ] Design system (colors, spacing, patterns)
- [ ] Current working icon URLs
- [ ] Activity tracking features
- [ ] Dashboard metrics explanation
- [ ] Service configuration
- [ ] Environment variables
- [ ] Common commands
- [ ] Deployment info
- [ ] Troubleshooting notes
- [ ] Notes for future AI instances

**Verification:**
CLAUDE.md should provide enough context for AI to understand project without prior knowledge.

---

### 5.5 Code Comments
**Requirements:**
- [ ] Complex functions have explanatory comments
- [ ] Database queries explained
- [ ] Security measures commented
- [ ] API endpoints documented
- [ ] Middleware functions explained
- [ ] No commented-out dead code
- [ ] TODO comments tracked

**Verification:**
```bash
# Check for excessive TODO comments
grep -r "TODO" server.js public/

# Check for commented-out code
grep -r "^[[:space:]]*//" server.js | wc -l
# Should be reasonable, not excessive
```

---

## 6. Performance Requirements

### 6.1 Response Times
**Requirements:**
- [ ] Login response < 500ms
- [ ] Dashboard load < 1s
- [ ] API endpoints < 200ms
- [ ] Service status checks timeout at 3s
- [ ] Database queries optimized with indexes
- [ ] Redis caching implemented
- [ ] No N+1 query problems

**Verification Steps:**
```bash
# Test response times
time curl http://localhost:3000/api/verify
time curl http://localhost:3000/api/services
time curl http://localhost:3000/api/status

# Check for slow queries in PostgreSQL logs
docker logs dashboard-postgres | grep "duration:" | sort -t: -k2 -n | tail -10
```

---

### 6.2 Caching Strategy
**Requirements:**
- [ ] Redis used for session storage
- [ ] Rate limiting backed by Redis
- [ ] Service status cached appropriately
- [ ] Cache invalidation on updates
- [ ] TTL set for cache entries

**Verification Steps:**
```bash
# Check Redis keys
docker exec -it dashboard-redis redis-cli -a local-dev-redis-password KEYS "*"

# Check TTL on keys
docker exec -it dashboard-redis redis-cli -a local-dev-redis-password TTL "some-key"
```

---

### 6.3 Database Performance
**Requirements:**
- [ ] All frequently queried columns indexed
- [ ] Foreign key indexes exist
- [ ] Compound indexes for multi-column queries
- [ ] Connection pooling configured
- [ ] Query execution plans optimized
- [ ] No full table scans on large tables

**Verification Steps:**
```bash
# Check all indexes
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT tablename, indexname FROM pg_indexes WHERE schemaname='public';"

# Analyze query plan for common queries
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "EXPLAIN ANALYZE SELECT * FROM users WHERE username = 'admin';"
```

---

## 7. Production Readiness

### 7.1 Environment Configuration
**Requirements:**
- [ ] .env.example file complete
- [ ] All required variables documented
- [ ] Secrets not hardcoded
- [ ] Default values appropriate
- [ ] Production vs development configs
- [ ] .env in .gitignore
- [ ] No secrets in git history

**Verification Steps:**
```bash
# Check .gitignore includes .env
cat .gitignore | grep "^\.env$"

# Check for secrets in git history
git log --all --full-history --source -- .env
# Should return nothing

# Verify .env.example is complete
diff <(grep "^[A-Z]" .env.example | cut -d= -f1 | sort) \
     <(grep "^[A-Z]" .env | cut -d= -f1 | sort)
# Should show only optional differences
```

---

### 7.2 Error Handling
**Requirements:**
- [ ] All try-catch blocks in async functions
- [ ] Database errors caught and logged
- [ ] User-friendly error messages
- [ ] No stack traces exposed to users
- [ ] 404 handler for unknown routes
- [ ] 500 handler for server errors
- [ ] Proper HTTP status codes
- [ ] Error logging to console/file

**Verification Steps:**
1. Test invalid routes → should get 404
2. Trigger database error → should get 500, no stack trace
3. Check console.error logs include details
4. Verify users see friendly messages, not technical errors

---

### 7.3 Logging
**Requirements:**
- [ ] Request logging (method, path, status, duration)
- [ ] Error logging (with stack traces server-side)
- [ ] Authentication events logged
- [ ] Security events logged (failed logins, etc.)
- [ ] PostgreSQL statement logging (development only)
- [ ] No sensitive data in logs (passwords, tokens)
- [ ] Log rotation configured (if file-based)

**Verification Steps:**
```bash
# Check server logs
docker logs dashboard-auth | head -50

# Check PostgreSQL logs
docker logs dashboard-postgres | grep "LOG:"

# Ensure no passwords in logs
docker logs dashboard-auth | grep -i "password"
# Should only show field names, not values
```

---

### 7.4 Docker Configuration
**Requirements:**
- [ ] Multi-stage Dockerfile (if applicable)
- [ ] Non-root user in container
- [ ] Health checks configured
- [ ] Resource limits set
- [ ] Volume mounts for persistence
- [ ] Networks properly configured
- [ ] Container restart policies
- [ ] No unnecessary packages

**Verification Steps:**
```bash
# Check health status
docker ps --format "table {{.Names}}\t{{.Status}}"

# Check resource limits
docker inspect dashboard-postgres | grep -A 10 "Memory"

# Check restart policy
docker inspect dashboard-redis | grep "RestartPolicy" -A 3
```

---

## 8. Testing Checklist

### 8.1 Authentication Flow
- [ ] Login with valid credentials → success
- [ ] Login with invalid credentials → error message
- [ ] Login with locked account → error message
- [ ] Logout → clears cookies, redirects to login
- [ ] Access protected route without token → redirect to login
- [ ] Access protected route with expired token → redirect to login
- [ ] Access protected route with valid token → success
- [ ] Session persists across page reloads
- [ ] Password must change flow works

---

### 8.2 User Management (Admin)
- [ ] Create user with all roles → success
- [ ] Create user with duplicate username → error
- [ ] Edit user display name → success
- [ ] Edit user email → success
- [ ] Change user role → success
- [ ] Reset user password → success
- [ ] Reset password with force change → user must change on next login
- [ ] Deactivate user → user cannot login
- [ ] Reactivate user → user can login
- [ ] Delete user with services → (behavior depends on cascade rules)

---

### 8.3 Service Management
- [ ] Create service (all types) → success
- [ ] Create service with duplicate path (both enabled) → error 409
- [ ] Create service with path from disabled service → success
- [ ] Edit service name → success
- [ ] Edit service category → success
- [ ] Edit service to invalid category → error 400
- [ ] Delete service → soft delete (enabled=false)
- [ ] Reuse path after delete → success
- [ ] Service status shows correctly
- [ ] Service activity shows correctly

---

### 8.4 Category Management
- [ ] Create category → success
- [ ] Create category with all icon/color options → success
- [ ] Edit category → success
- [ ] Delete category with no services → success
- [ ] Delete category with services → error (foreign key constraint)
- [ ] Assign services to category → success
- [ ] Categories show in correct display order

---

### 8.5 Dashboard & Monitoring
- [ ] Dashboard loads without errors
- [ ] Server metrics display correctly
- [ ] Service cards show for all enabled services
- [ ] Service status updates automatically
- [ ] Activity indicators work (green/gray)
- [ ] Last update timestamp updates
- [ ] Auto-refresh doesn't cause flickering
- [ ] Change detection prevents unnecessary updates
- [ ] Metrics bar shows all 7 metrics

---

### 8.6 Settings
- [ ] Change display name → success, navbar updates
- [ ] Change password with wrong current password → error
- [ ] Change password with correct current password → success
- [ ] Change password with confirmation mismatch → error
- [ ] Change password < 8 chars → error
- [ ] Still logged in after password change
- [ ] Can login with new password

---

## 9. Security Testing

### 9.1 SQL Injection Tests
- [ ] Username: `admin' OR '1'='1` → safely escaped
- [ ] Service name: `'; DROP TABLE users; --` → safely escaped
- [ ] All inputs with SQL syntax → safely handled

---

### 9.2 XSS Tests
- [ ] Display name: `<script>alert('XSS')</script>` → escaped/sanitized
- [ ] Service name with HTML → escaped/sanitized
- [ ] All user inputs properly escaped

---

### 9.3 CSRF Tests
- [ ] POST request without CSRF token → rejected
- [ ] POST request with invalid CSRF token → rejected
- [ ] POST request with valid CSRF token → accepted
- [ ] GET requests work without CSRF token

---

### 9.4 Authorization Tests
- [ ] Regular user cannot access /users → denied
- [ ] Regular user cannot create admin users → denied
- [ ] User cannot edit higher-privilege users → denied
- [ ] User can edit own profile → success

---

## 10. Audit Report Template

After completing audit, summarize:

```markdown
# MediaStack Dashboard - Audit Report
Date: [DATE]
Auditor: [NAME/AI]
Version: [GIT COMMIT HASH]

## Summary
- Total Checks: [X]
- Passed: [Y] ✅
- Failed: [Z] ❌
- Partial: [W] ⚠️
- Pass Rate: [Y/X * 100]%

## Critical Issues
[List any security or functionality issues]

## Warnings
[List any non-critical issues]

## Recommendations
[Improvements or enhancements]

## Conclusion
[Overall assessment of production readiness]
```

---

## How to Run This Audit

### Automated (AI-Assisted)
```
Please conduct a comprehensive audit of this project.
Follow the checklist in AUDIT_PROMPT.md.
Test each requirement and provide a detailed report.
```

### Manual
1. Clone repository
2. Set up local environment
3. Go through each section
4. Check code for requirements
5. Test functionality
6. Document results
7. Generate audit report

---

## Success Criteria

**Project is production-ready if:**
- ✅ All core functionality works
- ✅ All security requirements met
- ✅ Database properly configured
- ✅ Documentation complete
- ✅ No critical issues
- ✅ Pass rate > 95%
- ✅ All tests pass
- ✅ Performance acceptable
