# RBAC Integration Summary

## Overview
Successfully integrated Role-Based Access Control (RBAC) into `/opt/dashboard/server.js` with comprehensive user management endpoints and permission-based access control.

## Changes Made

### 1. Imports Added (Lines 21-31)
```javascript
const {
  requireRole,
  requirePermission,
  requireSuperAdmin,
  requireAdmin,
  requireCanManageUser,
  requireSelfOrAdmin,
  attachPermissions,
  ROLES,
  PERMISSIONS
} = require('./middleware/rbac');
```

### 2. Updated verifyToken Middleware (Lines 746-800)
- Changed from synchronous to async function
- Now fetches full user details from database including:
  - `role` - User's role (super_admin, admin, power_user, user, read_only)
  - `permissions` - Custom JSONB permissions array
  - `password_must_change` - Password change requirement flag
  - `is_active` - Account active status
- Populates `req.user` with complete user object for downstream middleware

### 3. Added Permission Helpers (Lines 802-804)
```javascript
app.use(attachPermissions());
```
This adds helper functions to all authenticated requests:
- `req.can(permission)` - Check if user has specific permission
- `req.hasRole(role)` - Check if user has specific role
- `req.hasAnyRole(roles)` - Check if user has any of the roles
- `req.canManage(targetRole)` - Check if user can manage target role

### 4. Updated Login Response (Lines 925-930)
Added `role` field to login response:
```javascript
res.json({
  success: true,
  username: user.username,
  role: user.role,  // NEW
  passwordMustChange: user.password_must_change === true
});
```

### 5. Protected Category Endpoints
- `POST /api/categories` - Requires `PERMISSIONS.CATEGORIES_CREATE`
- `PUT /api/categories/:id` - Requires `PERMISSIONS.CATEGORIES_EDIT`
- `DELETE /api/categories/:id` - Requires `PERMISSIONS.CATEGORIES_DELETE`

### 6. Protected Service Endpoints
- `POST /api/services` - Requires `PERMISSIONS.SERVICES_CREATE`
- `PUT /api/services/:id` - Requires `PERMISSIONS.SERVICES_EDIT`
- `DELETE /api/services/:id` - Requires `PERMISSIONS.SERVICES_DELETE`

### 7. New User Management Endpoints (Lines 1052-1299)

#### GET /api/users
- **Access:** Admin or higher
- **Returns:** List of all active users with details
- **Middleware:** `verifyToken`, `requireAdmin()`

#### POST /api/users
- **Access:** Users with `USERS_CREATE` permission
- **Creates:** New user account
- **Validation:**
  - Username and password required
  - Password strength validation (12+ chars, uppercase, lowercase, number, special char)
  - Role validation and assignment permission check
  - Prevents admins from creating super_admins
- **Middleware:** `verifyToken`, `requirePermission(PERMISSIONS.USERS_CREATE)`, `doubleCsrfProtection`

#### PUT /api/users/:id
- **Access:** Users who can manage the target user
- **Updates:** User profile (display_name, email, role, is_active)
- **Permission Check:** Uses `requireCanManageUser(pool)` to verify:
  - Current user can't modify themselves
  - Current user's role allows managing target user's role
- **Middleware:** `verifyToken`, `requireCanManageUser(pool)`, `doubleCsrfProtection`

#### DELETE /api/users/:id
- **Access:** Super admin only
- **Action:** Soft delete (sets `is_active = false`)
- **Protection:** Prevents self-deletion
- **Middleware:** `verifyToken`, `requireSuperAdmin()`, `doubleCsrfProtection`

#### PUT /api/users/:id/password
- **Access:** Users who can manage the target user
- **Resets:** User password
- **Options:** Can require password change on next login
- **Validation:** Password strength validation
- **Middleware:** `verifyToken`, `requireCanManageUser(pool)`, `doubleCsrfProtection`

## Role Hierarchy

```
super_admin (100) - Full system access
    ↓
admin (80) - Can manage users except super_admins
    ↓
power_user (60) - Can manage services/categories, view users
    ↓
user (40) - Can view and create services/categories
    ↓
read_only (20) - Can only view
```

## Permission Matrix

| Permission | super_admin | admin | power_user | user | read_only |
|------------|-------------|-------|------------|------|-----------|
| USERS_VIEW | ✓ | ✓ | ✓ | ✓ | ✗ |
| USERS_CREATE | ✓ | ✓ | ✗ | ✗ | ✗ |
| USERS_EDIT | ✓ | ✓ | ✗ | ✗ | ✗ |
| USERS_DELETE | ✓ | ✗ | ✗ | ✗ | ✗ |
| SERVICES_CREATE | ✓ | ✓ | ✓ | ✓ | ✗ |
| SERVICES_EDIT | ✓ | ✓ | ✓ | ✗ | ✗ |
| SERVICES_DELETE | ✓ | ✓ | ✓ | ✗ | ✗ |
| CATEGORIES_CREATE | ✓ | ✓ | ✓ | ✓ | ✗ |
| CATEGORIES_EDIT | ✓ | ✓ | ✓ | ✗ | ✗ |
| CATEGORIES_DELETE | ✓ | ✓ | ✓ | ✗ | ✗ |

## Database Requirements

### Admin Role Update
The existing admin user must be promoted to super_admin. Run:

```bash
docker exec -i dashboard-postgres psql -U dashboard_app -d dashboard < /opt/dashboard/database/update-admin-role.sql
```

Or manually:
```sql
UPDATE users SET role = 'super_admin' WHERE username = 'admin';
```

### Schema Expectations
The users table must have these columns (already exists):
- `id` - INTEGER PRIMARY KEY
- `username` - TEXT UNIQUE
- `password` - TEXT (bcrypt hash)
- `display_name` - TEXT
- `email` - TEXT
- `role` - TEXT (default: 'user')
- `permissions` - JSONB (custom permissions array)
- `is_active` - BOOLEAN (default: true)
- `password_must_change` - BOOLEAN
- `created_by` - INTEGER (foreign key to users.id)
- `created_at` - TIMESTAMP
- `updated_at` - TIMESTAMP

## Security Features

1. **Permission Validation:** All mutation endpoints check permissions before execution
2. **Role Hierarchy:** Higher roles can manage lower roles, but not vice versa
3. **Self-Protection:** Users cannot modify or delete their own accounts through admin endpoints
4. **CSRF Protection:** All state-changing endpoints require CSRF token
5. **Input Validation:** All inputs validated for length, format, and content
6. **Password Strength:** Enforced 12+ character passwords with complexity requirements
7. **Soft Delete:** Users are deactivated, not permanently deleted
8. **Audit Trail:** `created_by` field tracks who created each user

## Middleware Usage

### requireRole(roles)
```javascript
app.get('/api/admin-only', verifyToken, requireRole(ROLES.ADMIN), handler);
app.get('/api/super-or-admin', verifyToken, requireRole([ROLES.SUPER_ADMIN, ROLES.ADMIN]), handler);
```

### requirePermission(permissions)
```javascript
app.post('/api/services', verifyToken, requirePermission(PERMISSIONS.SERVICES_CREATE), handler);
app.put('/api/users/:id', verifyToken, requirePermission([PERMISSIONS.USERS_EDIT, PERMISSIONS.USERS_CREATE]), handler);
```

### requireSuperAdmin()
```javascript
app.delete('/api/users/:id', verifyToken, requireSuperAdmin(), handler);
```

### requireAdmin()
```javascript
app.get('/api/users', verifyToken, requireAdmin(), handler);
```

### requireCanManageUser(pool)
```javascript
app.put('/api/users/:id', verifyToken, requireCanManageUser(pool), handler);
```
This middleware:
- Fetches target user from database
- Checks if current user can manage target user's role
- Attaches target user to `req.targetUser` for use in handler
- Returns 403 if permission denied

## Testing Checklist

### Prerequisites
- [ ] Run `database/update-admin-role.sql` to promote admin to super_admin
- [ ] Restart dashboard container: `docker restart dashboard-auth`

### User Management
- [ ] GET /api/users - Admin can view all users
- [ ] POST /api/users - Admin can create users
- [ ] POST /api/users - Admin cannot create super_admin users
- [ ] PUT /api/users/:id - Admin can update user profiles
- [ ] PUT /api/users/:id - Admin cannot promote users to super_admin
- [ ] DELETE /api/users/:id - Only super_admin can delete users
- [ ] PUT /api/users/:id/password - Admin can reset passwords

### Service Management
- [ ] POST /api/services - Power_user can create services
- [ ] PUT /api/services/:id - Power_user can edit services
- [ ] DELETE /api/services/:id - Power_user can delete services
- [ ] POST /api/services - User role cannot create services (now protected)
- [ ] PUT /api/services/:id - User role cannot edit services (now protected)

### Category Management
- [ ] POST /api/categories - Power_user can create categories
- [ ] PUT /api/categories/:id - Power_user can edit categories
- [ ] DELETE /api/categories/:id - Power_user can delete categories
- [ ] POST /api/categories - User role cannot create categories (now protected)

### Permission Helpers
- [ ] `req.can('services:create')` returns correct boolean
- [ ] `req.hasRole('admin')` returns correct boolean
- [ ] `req.canManage('user')` returns correct boolean

## Files Created/Modified

### Modified
- `/opt/dashboard/server.js` - Integrated RBAC and added user management endpoints

### Created
- `/opt/dashboard/database/update-admin-role.sql` - SQL script to promote admin user

### Existing (No Changes)
- `/opt/dashboard/middleware/rbac.js` - RBAC middleware functions
- `/opt/dashboard/config/permissions.js` - Permission model and role hierarchy

## Next Steps

1. **Run Admin Role Update:**
   ```bash
   docker exec -i dashboard-postgres psql -U dashboard_app -d dashboard < database/update-admin-role.sql
   ```

2. **Restart Container:**
   ```bash
   docker restart dashboard-auth
   ```

3. **Verify Admin Role:**
   ```bash
   docker exec -it dashboard-postgres psql -U dashboard_app -d dashboard -c "SELECT username, role FROM users WHERE username = 'admin';"
   ```

4. **Test Endpoints:** Use Postman or curl to test the new user management endpoints

5. **Frontend Integration:** Create admin UI pages for user management (future task)

## API Examples

### Create User
```bash
curl -X POST https://arr.cirrolink.com/api/users \
  -H "Content-Type: application/json" \
  -H "Cookie: token=YOUR_JWT_TOKEN" \
  -d '{
    "username": "newuser",
    "password": "SecurePassword123!",
    "displayName": "New User",
    "email": "newuser@example.com",
    "role": "user"
  }'
```

### List Users
```bash
curl https://arr.cirrolink.com/api/users \
  -H "Cookie: token=YOUR_JWT_TOKEN"
```

### Update User Role
```bash
curl -X PUT https://arr.cirrolink.com/api/users/2 \
  -H "Content-Type: application/json" \
  -H "Cookie: token=YOUR_JWT_TOKEN" \
  -d '{
    "role": "power_user"
  }'
```

### Reset User Password
```bash
curl -X PUT https://arr.cirrolink.com/api/users/2/password \
  -H "Content-Type: application/json" \
  -H "Cookie: token=YOUR_JWT_TOKEN" \
  -d '{
    "newPassword": "NewSecurePassword123!",
    "requireChange": true
  }'
```

### Deactivate User
```bash
curl -X DELETE https://arr.cirrolink.com/api/users/2 \
  -H "Cookie: token=YOUR_JWT_TOKEN"
```

## Troubleshooting

### "Authentication required" error
- Ensure JWT token is valid and included in Cookie header
- Check that user account is active in database

### "Insufficient permissions" error
- Verify user role: `SELECT username, role FROM users WHERE id = YOUR_ID;`
- Check permission matrix above for required role
- Admins cannot create/modify super_admin users

### "User not found" error
- Verify user exists and is active: `SELECT * FROM users WHERE id = TARGET_ID;`
- Check that user hasn't been soft-deleted (is_active = false)

### "Cannot delete your own account" error
- This is expected behavior to prevent self-lockout
- Use a different admin account to deactivate your account if needed

## Notes

- All user management endpoints require CSRF token for state-changing operations
- User passwords are hashed with bcrypt (10 rounds)
- Failed login tracking and account locking continue to work as before
- The verifyToken middleware now makes an additional database query on each authenticated request to fetch full user details (consider caching if performance becomes an issue)
- Permission helpers are available on all authenticated routes via `req.can()`, `req.hasRole()`, etc.
