# Troubleshooting Guide

This document contains solutions to common issues encountered during development and deployment of MediaStack Dashboard.

## Table of Contents

1. [Authentication Issues](#authentication-issues)
2. [CSRF Token Errors](#csrf-token-errors)
3. [Service Management](#service-management)
4. [Category Management](#category-management)
5. [User Interface Issues](#user-interface-issues)
6. [Database Issues](#database-issues)
7. [Docker & Container Issues](#docker--container-issues)
8. [Icon & Display Issues](#icon--display-issues)
9. [Password & Security](#password--security)

---

## Authentication Issues

### Issue: "Manage Users" Redirects to Login Page

**Symptoms:**
- Clicking "Manage Users" link redirects to login page
- Login page shows "wrong auth" error
- Going back to dashboard shows user is still authenticated

**Root Cause:**
Missing route for `/users` page in server.js.

**Solution:**
Added route with authentication middleware in server.js:
```javascript
app.get('/users', verifyToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'users.html'));
});
```

**Committed:** Yes (check server.js around line 2093)

---

### Issue: Login Redirect Loop

**Symptoms:**
- Infinite redirect between login page and dashboard
- Cookies appear to be set but not recognized

**Root Cause:**
Cookie secure flag mismatch between HTTP (local) and HTTPS (production via Cloudflare).

**Solution:**
Ensure `app.set('trust proxy', 1)` is set in server.js and cookie configuration uses dynamic secure flag:
```javascript
res.cookie('token', token, {
  httpOnly: true,
  sameSite: 'lax',
  maxAge: 24 * 60 * 60 * 1000,
  secure: req.protocol === 'https' // Dynamic based on protocol
});
```

**Verification:**
- Check nginx preserves `X-Forwarded-Proto` header
- Check browser developer tools → Application → Cookies

---

## CSRF Token Errors

### Issue: "Invalid CSRF Token" on All POST/PUT/DELETE Operations

**Symptoms:**
- All state-changing operations fail with 500 Internal Server Error
- Server logs show: `ForbiddenError: invalid csrf token`
- Occurs on user creation, updates, service edits, etc.

**Root Cause (3 iterations):**

**Iteration 1 - Wrong Option Name:**
Used `getTokenFromRequest` instead of `getCsrfTokenFromRequest` in CSRF configuration.

**Fix 1:**
Changed to correct option name, but still had errors.

**Iteration 2 - Explicit Override Issue:**
Explicitly overriding default token extraction caused initialization errors.

**Fix 2:**
Removed explicit `getCsrfTokenFromRequest` option entirely to use library defaults. Server started clean but operations still failed.

**Iteration 3 - Session Identifier Mismatch:**
Session identifier was different when generating vs validating tokens:
- CSRF token fetch (no auth): `req.user?.id || 'anonymous'` → 'anonymous'
- Form submission (with auth): `req.user?.id || 'anonymous'` → user ID
- Different identifiers = validation fails

**Final Fix:**
Changed `getSessionIdentifier` to use JWT cookie value (consistent across all requests):
```javascript
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => csrfSecret,
  cookieName: 'csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    path: '/',
    secure: false,
    httpOnly: true
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getSessionIdentifier: (req) => {
    return req.cookies.token || 'anonymous';
  }
});
```

**Committed:** Yes (commit a2121b8)

**Verification:**
```bash
# Check server logs for CSRF errors
docker logs dashboard-auth --tail 100 | grep csrf

# Test CSRF token endpoint
curl -c cookies.txt http://localhost:3000/api/csrf-token
curl -b cookies.txt -H "Content-Type: application/json" \
  -H "x-csrf-token: TOKEN_FROM_ABOVE" \
  -d '{"username":"admin","password":"Admin123!"}' \
  http://localhost:3000/api/login
```

---

## Service Management

### Issue: Cannot Assign Custom Categories to Services (400 Error)

**Symptoms:**
- Creating or editing service with newly created category fails
- Browser console: `Failed to load resource: 400`
- Error message: "Invalid category"

**Root Cause:**
Hardcoded category validation checking against fixed list instead of database:
```javascript
const validCategories = ['contentManagement', 'downloadClients', 'managementAnalytics'];
if (!validCategories.includes(category)) {
  return res.status(400).json({ error: 'Invalid category' });
}
```

**Solution:**
Replaced with database validation in both POST and PUT service endpoints (server.js lines 1605-1610 and 1703-1708):
```javascript
// Validate category exists in database
const categoryCheck = await pool.query('SELECT id FROM categories WHERE id = $1', [category]);
if (categoryCheck.rows.length === 0) {
  return res.status(400).json({ error: 'Invalid category: category does not exist' });
}
```

**Committed:** Yes (commit 19e98c3)

**Verification:**
1. Create a new category in Admin page
2. Create or edit a service
3. Assign the new category
4. Save - should succeed

---

### Issue: "Service with This Path Already Exists" (409 Error)

**Symptoms:**
- Creating new service fails with 409 Conflict error
- Error: "Service with this path already exists"
- Path was previously used by a disabled or deleted service

**Root Cause:**
Global unique constraint on `path` column applied to ALL rows (enabled and disabled):
```sql
CONSTRAINT services_path_key UNIQUE (path)
```

**Solution:**
Changed to partial unique index that only enforces uniqueness for enabled services:

1. **Migration file created:** `database/migrations/001_fix_service_path_unique_constraint.sql`
```sql
-- Drop the old unique constraint
ALTER TABLE services DROP CONSTRAINT IF EXISTS services_path_key;

-- Create partial unique index for enabled services only
CREATE UNIQUE INDEX IF NOT EXISTS services_path_enabled_unique
ON services(path)
WHERE enabled = true;
```

2. **Applied migration:**
```bash
docker exec -i dashboard-postgres psql -U dashboard_app -d dashboard < \
  database/migrations/001_fix_service_path_unique_constraint.sql
```

**Committed:** Yes (commit 1d15e01)

**Verification:**
```bash
# Check disabled services
docker exec dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT id, name, path, enabled FROM services WHERE enabled = false;"

# Check unique index exists
docker exec dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "\d services"
# Look for: services_path_enabled_unique
```

**Result:**
Paths can now be reused from disabled/deleted services.

---

### Issue: Services Show Offline Despite Being Online

**Symptoms:**
- All services show red "OFFLINE" status
- Services are running and accessible
- API keys are configured

**Root Cause:**
One of the following:
1. Missing or incorrect API keys in `.env`
2. Wrong API URL in service configuration
3. Service API endpoint changed
4. Network connectivity issue from container

**Solution:**

**Step 1 - Verify API Keys:**
```bash
# Check environment variables are loaded
docker exec dashboard-auth env | grep API_KEY

# Verify keys match service settings
# Example for Sonarr: Settings → General → API Key
```

**Step 2 - Test API Connectivity:**
```bash
# Test from container (replace with your service details)
docker exec dashboard-auth wget -O- \
  --header="X-Api-Key: your-api-key" \
  http://sonarr:8989/api/v3/system/status

# Test from host
curl -H "X-Api-Key: your-api-key" \
  http://localhost:8989/api/v3/system/status
```

**Step 3 - Check Service Configuration:**
1. Go to Admin page
2. Edit service
3. Verify API URL is correct (e.g., `http://sonarr:8989`)
4. Verify API Key Environment Variable name matches `.env`

**Step 4 - Verify Network:**
```bash
# Check container can reach services
docker exec dashboard-auth ping -c 3 sonarr
docker exec dashboard-auth nslookup sonarr
```

**Step 5 - Check Server Logs:**
```bash
docker logs dashboard-auth --tail 50 | grep -i "status check"
```

---

## Category Management

### Issue: Cannot Delete Category (Foreign Key Constraint)

**Symptoms:**
- Deleting category fails with error
- Error message: "Cannot delete category with assigned services"

**Root Cause:**
Foreign key constraint prevents deleting categories that have services assigned.

**Solution:**
This is expected behavior to maintain data integrity. To delete a category:

1. **Option A - Reassign Services:**
   - Edit each service assigned to the category
   - Change to a different category
   - Then delete the category

2. **Option B - Delete Services First:**
   - Delete or disable all services in the category
   - Then delete the category

**Verification:**
```bash
# Check which services use the category
docker exec dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT s.id, s.name, c.name as category
      FROM services s
      JOIN categories c ON s.category_id = c.id
      WHERE c.id = YOUR_CATEGORY_ID;"
```

---

## User Interface Issues

### Issue: Buttons Don't Show Feedback (Lead to Nothing)

**Symptoms:**
- Clicking save/delete/create buttons appears to do nothing
- Operations actually complete in backend
- No success or error messages shown

**Root Cause:**
Code used old `showGlobalMessage()` function that doesn't exist instead of new toast notification system.

**Solution:**
Updated all CRUD functions in `public/js/users.js` to use toast notifications:
```javascript
// Instead of:
showGlobalMessage('Success', 'success');

// Use:
showSuccess('User created successfully');
showError('Failed to create user');
```

**Fixed Functions:**
- `createUser()` - lines 372, 377
- `updateUser()` - lines 413, 418
- `resetPassword()` - lines 450, 454
- `deleteUser()` - lines 483, 488
- `loadUsers()` - line 267

**Committed:** Yes

**Verification:**
After fix, all operations should show green success toasts or red error toasts in top-right corner.

---

### Issue: UI Feels Unresponsive or "Dead"

**Symptoms:**
- No visual feedback on hover
- Buttons don't animate on click
- Modals appear/disappear instantly
- Application feels static

**Root Cause:**
Missing CSS animations, transitions, and interactive states.

**Solution:**
Added comprehensive UX improvements:

1. **Button Animations** (admin.css, users.css):
```css
.primary-btn:hover {
  background: #2ea043;
  transform: translateY(-1px);
  box-shadow: 0 4px 8px rgba(35, 134, 54, 0.3);
}
.primary-btn:active {
  transform: translateY(0);
  box-shadow: none;
}
```

2. **Modal Animations**:
```css
.modal.show {
  animation: fadeIn 0.3s ease forwards;
}
.modal-content {
  transform: scale(0.9) translateY(-20px);
  opacity: 0;
  transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}
.modal.show .modal-content {
  transform: scale(1) translateY(0);
  opacity: 1;
}
```

3. **Toast Notification System** (+100 lines in users.css):
```css
.toast {
  animation: slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}
```

4. **Form Focus Effects**:
```css
input:focus, select:focus, textarea:focus {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}
```

**Committed:** Yes

---

### Issue: Category Modal Not Showing/Hiding Properly

**Symptoms:**
- Click "Add Category" but modal doesn't appear
- Modal appears but won't close
- Modal animation doesn't work

**Root Cause:**
Using `style.display` instead of CSS class for modal visibility, which conflicts with CSS animations.

**Solution:**
Changed modal control to use `classList.add/remove('show')` instead of `style.display`:

```javascript
// Open modal
categoryModal.classList.add('show');

// Close modal
categoryModal.classList.remove('show');
```

**Fixed Locations in admin.js:**
- Add category button: line 876
- Close modal buttons: lines 883, 885
- Background click: line 891
- Edit category function: line 900
- Save success: line 937

**Verification:**
1. Click "Add Category" - modal should fade in with scale animation
2. Click outside modal or close button - modal should fade out smoothly

---

### Issue: Inconsistent Colors Across Pages

**Symptoms:**
- Different shades of gray/blue on different pages
- Hover states use different colors
- Modal overlays have different opacity

**Root Cause:**
Some CSS files created before design system (variables.css) was established, using hardcoded colors.

**Solution:**
Replaced all hardcoded colors with CSS variables in admin.css and users.css:

```css
/* Before */
background: #0d1117;
border: 1px solid #30363d;
color: #c9d1d9;

/* After */
background: var(--color-bg-primary);
border: 1px solid var(--color-border);
color: var(--color-text-primary);
```

**Committed:** Yes

**Color Variables Reference (variables.css):**
- `--color-bg-primary: #0d1117` - Main background
- `--color-bg-secondary: #161b22` - Cards/panels
- `--color-border: #30363d` - Borders
- `--color-text-primary: #c9d1d9` - Primary text
- `--color-text-secondary: #8b949e` - Secondary text
- `--color-accent: #58a6ff` - Links, focus states
- `--color-success: #3fb950` - Success states
- `--color-danger: #f85149` - Errors, danger actions

---

## Database Issues

### Issue: Migration from SQLite to PostgreSQL

**Symptoms:**
- Application was using SQLite (`data/users.db`)
- Need to migrate to PostgreSQL for production

**Solution:**
Migration script created at `database/migrate-sqlite-to-postgres.js`:

```bash
# Set environment variables for PostgreSQL connection
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=dashboard
export POSTGRES_USER=dashboard_app
export POSTGRES_PASSWORD=your-password

# Run migration
node database/migrate-sqlite-to-postgres.js
```

**Manual Verification:**
```bash
# Check users migrated
docker exec dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT id, username, display_name FROM users;"

# Check services migrated
docker exec dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT id, name, path FROM services WHERE enabled = true;"

# Check categories migrated
docker exec dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT id, name, icon FROM categories ORDER BY display_order;"
```

---

### Issue: Connection Pool Exhausted

**Symptoms:**
- Application becomes unresponsive after heavy use
- Error: "Connection pool exhausted"

**Root Cause:**
Database connections not being released properly.

**Solution:**
Ensure all database queries release connections:

```javascript
// Bad - doesn't release on error
const result = await pool.query('SELECT * FROM users');

// Good - releases even on error
let client;
try {
  client = await pool.connect();
  const result = await client.query('SELECT * FROM users');
  // ... use result
} finally {
  if (client) client.release();
}
```

**Verification:**
```bash
# Check active connections
docker exec dashboard-postgres psql -U dashboard_app -d dashboard \
  -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'dashboard';"
```

---

## Docker & Container Issues

### Issue: Container Won't Start After Restart

**Symptoms:**
- `docker restart dashboard-auth` fails
- Container status shows "Restarting" or "Exited"

**Solution:**

**Step 1 - Check Logs:**
```bash
docker logs dashboard-auth --tail 100
```

**Common Errors:**

**Error: "Cannot find module 'bcrypt'"**
- Switch to bcryptjs (Alpine Linux compatible)
- Update package.json: `"bcryptjs": "^2.4.3"`
- Update server.js: `const bcrypt = require('bcryptjs');`
- Run: `docker exec dashboard-auth npm install`

**Error: "EADDRINUSE: Port 3000 already in use"**
```bash
# Find process using port
docker ps | grep 3000
# Stop conflicting container
docker stop <container-id>
```

**Error: "Connection refused to PostgreSQL"**
```bash
# Verify PostgreSQL is running
docker ps | grep dashboard-postgres
# Start if needed
docker start dashboard-postgres
# Wait 5 seconds for PostgreSQL to initialize
sleep 5
docker restart dashboard-auth
```

**Step 2 - Full Restart:**
```bash
docker stop dashboard-auth
docker rm dashboard-auth
# Recreate container (use your original docker run command)
docker run -d --name dashboard-auth ...
```

---

### Issue: Node Modules Missing After Code Changes

**Symptoms:**
- Application crashes with "Cannot find module" errors
- Happens after updating package.json

**Solution:**
```bash
# Rebuild node modules inside container
docker exec dashboard-auth npm install

# If that fails, install specific package
docker exec dashboard-auth npm install bcryptjs

# Restart container
docker restart dashboard-auth
```

---

## Icon & Display Issues

### Issue: Service Icons Not Displaying

**Symptoms:**
- Broken image icon shows instead of service logo
- Empty square where icon should be

**Root Cause:**
Icon URL is incorrect, broken, or blocked by CORS.

**Solution:**

**Step 1 - Verify Icon URL:**
```bash
# Test if URL is accessible
curl -I https://raw.githubusercontent.com/Sonarr/Sonarr/develop/Logo/128.png
# Should return HTTP 200
```

**Step 2 - Use Verified Icon Sources:**
Prefer walkxcode/dashboard-icons (verified working):
```
https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/sonarr.png
https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/radarr.png
https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/plex.png
```

**Step 3 - Update Service:**
1. Go to Admin page
2. Edit service
3. Update Icon URL
4. Save
5. Refresh dashboard

**Step 4 - Check Browser Console:**
- Open DevTools (F12)
- Check Console for CORS errors
- Check Network tab for failed image requests

---

### Issue: Sonarr Anime Icon Same as Regular Sonarr

**Symptoms:**
- Sonarr Anime icon looks identical to regular Sonarr
- Can't distinguish between the two instances

**Solution:**
Use CSS filter to create visual distinction (dashboard.css lines 241-243):

```css
.service-card img[alt*="Anime"] {
  filter: hue-rotate(280deg) saturate(1.8) brightness(1.1);
}
```

This creates a pink/purple tint while keeping the same base icon.

**DO NOT:**
- Add borders or backgrounds
- Create custom SVG backgrounds
- Use inline SVG data URIs

---

## Password & Security

### Issue: Locked Out (Forgot Admin Password)

**Solution:**
Reset password using bcryptjs hash:

```bash
# Generate new password hash
docker exec dashboard-auth node -e \
  "const bcrypt = require('bcryptjs'); console.log(bcrypt.hashSync('NewPassword123!', 10));"

# Copy the output hash, then update database
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard

UPDATE users
SET password = 'paste-hash-here'
WHERE username = 'admin';
```

**Default Credentials:**
- Username: `admin`
- Password: `Admin123!`

---

### Issue: "Current password is incorrect" When Changing Password

**Symptoms:**
- Know current password is correct
- Password change fails validation

**Root Cause:**
Password hashing mismatch if migrated from bcrypt to bcryptjs without rehashing.

**Solution:**
Reset password as admin or use database update method above.

---

### Issue: bcrypt SIGSEGV Error on Alpine Linux

**Symptoms:**
- Container crashes with segmentation fault
- Logs show: "SIGSEGV" or "Segmentation fault"
- Happens during login or password operations

**Root Cause:**
Native bcrypt module incompatible with Alpine Linux (musl libc).

**Solution:**
Switch to bcryptjs (pure JavaScript implementation):

1. **Update package.json:**
```json
{
  "dependencies": {
    "bcryptjs": "^2.4.3"
  }
}
```

2. **Update server.js (line 3):**
```javascript
const bcrypt = require('bcryptjs');
```

3. **Install:**
```bash
docker exec dashboard-auth npm install bcryptjs
docker restart dashboard-auth
```

4. **Rehash all passwords:**
Passwords hashed with old bcrypt won't work. Users need password reset.

---

## General Debugging Commands

### Check Application Logs
```bash
# Real-time logs
docker logs dashboard-auth -f

# Last 100 lines
docker logs dashboard-auth --tail 100

# Since 5 minutes ago
docker logs dashboard-auth --since 5m

# Search for errors
docker logs dashboard-auth | grep -i error
```

### Check Database
```bash
# Connect to PostgreSQL
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard

# Useful queries
SELECT * FROM users;
SELECT * FROM services WHERE enabled = true;
SELECT * FROM categories ORDER BY display_order;
SELECT * FROM roles;

# Check for disabled services blocking paths
SELECT id, name, path, enabled FROM services WHERE enabled = false;
```

### Check Redis Cache
```bash
# Connect to Redis
docker exec -it dashboard-redis redis-cli

# View all keys
KEYS *

# Get specific cached data
GET services:all

# Clear cache
FLUSHDB
```

### Check Network Connectivity
```bash
# Test from container
docker exec dashboard-auth ping -c 3 sonarr
docker exec dashboard-auth wget -O- http://sonarr:8989/api/v3/system/status

# Check container network
docker network inspect arr-proxy_arr-network
```

### Check Environment Variables
```bash
# List all environment variables
docker exec dashboard-auth env

# Check specific variables
docker exec dashboard-auth env | grep API_KEY
docker exec dashboard-auth env | grep JWT_SECRET
```

---

## Getting More Help

If you encounter an issue not covered here:

1. **Check Server Logs** - Most issues show detailed errors in logs
2. **Check Browser Console** - Frontend errors appear in DevTools console
3. **Review Recent Changes** - Check git log for what changed recently
4. **Check DEVELOPMENT.md** - Development setup and workflow guide
5. **Check CLAUDE.md** - Architecture and implementation details

**Security Issues:** soufiane.hmiad@outlook.com
