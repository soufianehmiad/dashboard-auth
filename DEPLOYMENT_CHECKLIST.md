# RBAC Integration Deployment Checklist

## Pre-Deployment Verification

- [x] All files have valid Node.js syntax
  - server.js: ✓
  - middleware/rbac.js: ✓
  - config/permissions.js: ✓

- [x] RBAC middleware imported correctly in server.js
- [x] verifyToken middleware updated to fetch role and permissions
- [x] attachPermissions() middleware added globally
- [x] Login endpoint returns user role
- [x] All category endpoints protected with permission checks
- [x] All service endpoints protected with permission checks
- [x] All user management endpoints implemented
- [x] CSRF protection applied to all state-changing operations

## Deployment Steps

### Step 1: Update Admin User Role
```bash
# Run the SQL migration to promote admin user to super_admin
docker exec -i dashboard-postgres psql -U dashboard_app -d dashboard < /opt/dashboard/database/update-admin-role.sql
```

**Expected Output:**
```
UPDATE 1
 id | username |    role     |         created_at
----+----------+-------------+----------------------------
  1 | admin    | super_admin | 2025-01-XX XX:XX:XX.XXXXXX
(1 row)
```

### Step 2: Verify Database State
```bash
# Check admin user role
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard -c \
  "SELECT id, username, role, is_active FROM users WHERE username = 'admin';"
```

**Expected Output:**
```
 id | username |    role     | is_active
----+----------+-------------+-----------
  1 | admin    | super_admin | t
(1 row)
```

### Step 3: Restart Dashboard Container
```bash
docker restart dashboard-auth
```

### Step 4: Check Container Logs
```bash
docker logs dashboard-auth --tail 50
```

**Expected Output (should include):**
```
✓ Connected to PostgreSQL database
✓ Connected to Redis
Dashboard server running on port 3000
JWT_SECRET: [CONFIGURED] (XX characters)
```

### Step 5: Test Authentication
```bash
# Login as admin (replace with actual password)
curl -X POST https://arr.cirrolink.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}' \
  -c cookies.txt -v
```

**Expected Response:**
```json
{
  "success": true,
  "username": "admin",
  "role": "super_admin",
  "passwordMustChange": false
}
```

### Step 6: Test User Management Endpoints

#### Test GET /api/users (Admin Access)
```bash
curl https://arr.cirrolink.com/api/users \
  -H "Cookie: token=$(cat cookies.txt | grep token | awk '{print $7}')" \
  -v
```

**Expected:** 200 OK with list of users

#### Test POST /api/users (Create User)
```bash
# Get CSRF token first
curl https://arr.cirrolink.com/api/csrf-token \
  -b cookies.txt -c cookies.txt

curl -X POST https://arr.cirrolink.com/api/users \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "TestPassword123!",
    "displayName": "Test User",
    "email": "test@example.com",
    "role": "user"
  }'
```

**Expected:** 201 Created with user object

### Step 7: Test Permission Checks

#### Test as Non-Admin User (Should Fail)
```bash
# Login as testuser
curl -X POST https://arr.cirrolink.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"TestPassword123!"}' \
  -c testuser-cookies.txt

# Try to access admin-only endpoint
curl https://arr.cirrolink.com/api/users \
  -b testuser-cookies.txt
```

**Expected:** 403 Forbidden
```json
{
  "error": "Insufficient permissions",
  "message": "You do not have permission to perform this action"
}
```

### Step 8: Test Service Creation Permissions

#### As Power User (Should Succeed)
```bash
# First, promote testuser to power_user using admin account
curl -X PUT https://arr.cirrolink.com/api/users/2 \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"role": "power_user"}'

# Login as testuser again to get new role in token
curl -X POST https://arr.cirrolink.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"TestPassword123!"}' \
  -c testuser-cookies.txt

# Try to create a service
curl -X POST https://arr.cirrolink.com/api/services \
  -b testuser-cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Service",
    "path": "/test",
    "icon_url": "https://example.com/icon.png",
    "category": "contentManagement",
    "service_type": "external"
  }'
```

**Expected:** 201 Created (power_user has SERVICES_CREATE permission)

## Post-Deployment Verification

### Verify All Endpoints

| Endpoint | Method | Role Required | Test Status |
|----------|--------|---------------|-------------|
| /api/users | GET | Admin+ | [ ] |
| /api/users | POST | Admin+ | [ ] |
| /api/users/:id | PUT | Admin+ | [ ] |
| /api/users/:id | DELETE | Super Admin | [ ] |
| /api/users/:id/password | PUT | Admin+ | [ ] |
| /api/categories | POST | Power User+ | [ ] |
| /api/categories/:id | PUT | Power User+ | [ ] |
| /api/categories/:id | DELETE | Power User+ | [ ] |
| /api/services | POST | Power User+ | [ ] |
| /api/services/:id | PUT | Power User+ | [ ] |
| /api/services/:id | DELETE | Power User+ | [ ] |

### Verify Permission Matrix

| User Role | Can Create Users | Can Edit Services | Can Delete Users | Can View Users |
|-----------|------------------|-------------------|------------------|----------------|
| super_admin | ✓ | ✓ | ✓ | ✓ |
| admin | ✓ | ✓ | ✗ | ✓ |
| power_user | ✗ | ✓ | ✗ | ✓ |
| user | ✗ | ✗ | ✗ | ✓ |
| read_only | ✗ | ✗ | ✗ | ✗ |

Test each combination: [ ]

### Security Checks

- [ ] CSRF token required for all POST/PUT/DELETE operations
- [ ] Users cannot delete their own accounts
- [ ] Admins cannot create super_admin users
- [ ] Admins cannot promote users to super_admin
- [ ] Password strength validation enforced (12+ chars, complexity)
- [ ] Invalid roles rejected with 400 error
- [ ] Inactive users cannot authenticate
- [ ] All sensitive data sanitized in logs

## Rollback Plan

If issues occur, rollback using:

```bash
# Restore previous version of server.js from git
cd /opt/dashboard
git checkout HEAD~1 server.js

# Restart container
docker restart dashboard-auth
```

## Monitoring

### Check Application Logs
```bash
# Real-time logs
docker logs -f dashboard-auth

# Check for errors
docker logs dashboard-auth | grep -i error | tail -20
```

### Check Database Connections
```bash
# Check active connections
docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard -c \
  "SELECT count(*) FROM pg_stat_activity WHERE datname = 'dashboard';"
```

### Check Redis Connections
```bash
# Check Redis connection
docker exec -it dashboard-redis redis-cli -a $REDIS_PASSWORD ping
```

## Known Issues & Solutions

### Issue: "User not found" after login
**Cause:** JWT token contains old user ID that doesn't exist in database
**Solution:** Clear cookies and login again

### Issue: "Insufficient permissions" for admin user
**Cause:** Admin user not promoted to super_admin
**Solution:** Run Step 1 again (update-admin-role.sql)

### Issue: "Authentication required" for all requests
**Cause:** verifyToken middleware failing to fetch user from database
**Solution:** Check PostgreSQL connection and user table schema

### Issue: Container won't start
**Cause:** Syntax error in server.js
**Solution:** Run `node -c server.js` to check syntax, rollback if needed

## Success Criteria

Deployment is successful when:

1. [x] All syntax checks pass
2. [ ] Admin user has super_admin role in database
3. [ ] Container starts without errors
4. [ ] Login returns user role in response
5. [ ] Admin can access /api/users endpoint
6. [ ] Permission checks block unauthorized users
7. [ ] All CRUD operations work for authorized users
8. [ ] CSRF protection working on state-changing operations
9. [ ] No errors in container logs
10. [ ] Existing dashboard functionality still works

## Contact

If you encounter issues not covered in this checklist, check:
- `/opt/dashboard/RBAC_INTEGRATION_SUMMARY.md` - Detailed technical documentation
- Container logs: `docker logs dashboard-auth`
- Database logs: `docker logs dashboard-postgres`
