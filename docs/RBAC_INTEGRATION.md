# RBAC Integration - Phase 3 Complete

## Overview

The dashboard application now features a comprehensive Role-Based Access Control (RBAC) system, providing fine-grained permission management for multi-user deployments.

**Integration Date:** 2025-11-13
**Integration Status:** ✅ Complete

---

## Benefits of RBAC Integration

### 1. **Security Improvements**
- **Principle of Least Privilege**: Users only have access to features they need
- **Hierarchical Role System**: 5 distinct roles from read-only to super admin
- **Granular Permissions**: 20+ individual permissions for precise access control
- **Protected User Management**: Admins cannot elevate privileges or delete super admins
- **Audit-Ready**: All user actions can be tracked with role context

### 2. **Multi-User Support**
- **User Management API**: Create, update, deactivate users via REST endpoints
- **Password Management**: Admins can reset passwords with optional force-change
- **Role Assignment**: Super admins and admins can assign appropriate roles
- **User Isolation**: Users cannot modify others unless authorized
- **Account Deactivation**: Soft delete maintains data integrity

### 3. **Enterprise Readiness**
- **Flexible Permission Model**: Role-based + custom permissions support
- **Middleware Architecture**: Easy to protect any endpoint with RBAC
- **Role Hierarchy**: Clear privilege levels prevent privilege escalation
- **Extensible Design**: New permissions easily added without code changes
- **API-First Design**: All user management operations available via REST API

---

## Architecture

### Role Hierarchy

The RBAC system implements a five-tier hierarchical role model with numeric privilege levels:

| Role | Level | Display Name | Description |
|------|-------|--------------|-------------|
| `super_admin` | 100 | Super Administrator | Full system access, can manage all users including other admins |
| `admin` | 80 | Administrator | Can manage users, services, and categories (except super admins) |
| `power_user` | 60 | Power User | Can manage services and categories, view users |
| `user` | 40 | User | Can view and create services/categories, edit own profile |
| `read_only` | 20 | Read Only | Can only view services and categories |

**Hierarchy Rules:**
- Higher privilege level can perform actions of lower levels
- Users cannot modify users with equal or higher privilege level
- Only super_admin can delete users or promote to super_admin
- Admins cannot manage other admins or super_admins

---

## Permission Model

### Permission Categories

The system defines 20 granular permissions across 6 categories:

#### User Management (5 permissions)
- `users:view` - List and view user profiles
- `users:create` - Create new user accounts
- `users:edit` - Update user profiles (display name, email, role)
- `users:delete` - Deactivate user accounts
- `users:change_role` - Change user roles

#### Service Management (4 permissions)
- `services:view` - View service configurations
- `services:create` - Add new services
- `services:edit` - Update service settings
- `services:delete` - Remove services

#### Category Management (4 permissions)
- `categories:view` - View category list
- `categories:create` - Create new categories
- `categories:edit` - Update category settings
- `categories:delete` - Remove categories

#### API Key Management (3 permissions)
- `api_keys:view` - View API keys (not implemented yet)
- `api_keys:create` - Generate new API keys (not implemented yet)
- `api_keys:revoke` - Revoke API keys (not implemented yet)

#### System Settings (2 permissions)
- `settings:view` - View system settings
- `settings:edit` - Modify system configuration

#### Audit Logs (2 permissions)
- `audit:view` - View audit log entries (not implemented yet)
- `audit:export` - Export audit logs (not implemented yet)

---

## Roles & Permissions Matrix

### Complete Permission Assignment

| Permission | super_admin | admin | power_user | user | read_only |
|------------|-------------|-------|------------|------|-----------|
| **Users** |
| users:view | ✅ | ✅ | ✅ | ✅ | ❌ |
| users:create | ✅ | ✅ | ❌ | ❌ | ❌ |
| users:edit | ✅ | ✅ | ❌ | ❌ | ❌ |
| users:delete | ✅ | ❌ | ❌ | ❌ | ❌ |
| users:change_role | ✅ | ❌* | ❌ | ❌ | ❌ |
| **Services** |
| services:view | ✅ | ✅ | ✅ | ✅ | ✅ |
| services:create | ✅ | ✅ | ✅ | ✅ | ❌ |
| services:edit | ✅ | ✅ | ✅ | ❌ | ❌ |
| services:delete | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Categories** |
| categories:view | ✅ | ✅ | ✅ | ✅ | ✅ |
| categories:create | ✅ | ✅ | ✅ | ✅ | ❌ |
| categories:edit | ✅ | ✅ | ✅ | ❌ | ❌ |
| categories:delete | ✅ | ✅ | ✅ | ❌ | ❌ |
| **API Keys** |
| api_keys:view | ✅ | ✅ | ✅ | ❌ | ❌ |
| api_keys:create | ✅ | ✅ | ❌ | ❌ | ❌ |
| api_keys:revoke | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Settings** |
| settings:view | ✅ | ✅ | ✅ | ✅ | ✅ |
| settings:edit | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Audit** |
| audit:view | ✅ | ✅ | ❌ | ❌ | ❌ |
| audit:export | ✅ | ❌ | ❌ | ❌ | ❌ |

**Note:** Admins can change roles except to/from super_admin

---

## API Endpoints

### User Management Endpoints

All user management endpoints require authentication via JWT token.

#### 1. GET /api/users

**Description:** List all active users

**Authorization:** Admin or higher (`requireAdmin()`)

**Response:**
```json
[
  {
    "id": 1,
    "username": "admin",
    "display_name": "System Administrator",
    "email": "admin@example.com",
    "role": "super_admin",
    "last_login_at": "2025-11-13T15:30:00.000Z",
    "last_login_ip": "10.99.0.1",
    "failed_login_attempts": 0,
    "locked_until": null,
    "is_active": true,
    "created_at": "2025-11-01T10:00:00.000Z"
  },
  {
    "id": 2,
    "username": "john_doe",
    "display_name": "John Doe",
    "email": "john@example.com",
    "role": "user",
    "last_login_at": "2025-11-13T14:00:00.000Z",
    "last_login_ip": "10.99.0.5",
    "failed_login_attempts": 0,
    "locked_until": null,
    "is_active": true,
    "created_at": "2025-11-10T09:00:00.000Z"
  }
]
```

**Example:**
```bash
curl http://localhost:3000/api/users \
  -H "Cookie: token=your-jwt-token"
```

---

#### 2. POST /api/users

**Description:** Create a new user account

**Authorization:** `requirePermission(PERMISSIONS.USERS_CREATE)` (admin or higher)

**Request Body:**
```json
{
  "username": "jane_smith",
  "password": "SecurePass123!",
  "displayName": "Jane Smith",
  "email": "jane@example.com",
  "role": "power_user"
}
```

**Validation:**
- `username`: Required, 3-50 characters, alphanumeric + underscore
- `password`: Required, minimum 8 characters
- `displayName`: Optional, max 100 characters
- `email`: Optional, valid email format, unique
- `role`: Optional, defaults to 'user', must be valid role value

**Response (201 Created):**
```json
{
  "success": true,
  "userId": 3,
  "username": "jane_smith",
  "message": "User created successfully"
}
```

**Errors:**
- `400`: Missing username/password, invalid format, username/email already exists
- `403`: Insufficient permissions or attempting to create super_admin without permission

**Example:**
```bash
curl -X POST http://localhost:3000/api/users \
  -H "Cookie: token=your-jwt-token" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: your-csrf-token" \
  -d '{
    "username": "jane_smith",
    "password": "SecurePass123!",
    "displayName": "Jane Smith",
    "email": "jane@example.com",
    "role": "power_user"
  }'
```

---

#### 3. PUT /api/users/:id

**Description:** Update user profile (display name, email, role, status)

**Authorization:** `requireCanManageUser(pool)` - checks if current user can manage target user

**Request Body:**
```json
{
  "displayName": "Jane M. Smith",
  "email": "jane.smith@example.com",
  "role": "admin",
  "isActive": true
}
```

**Validation:**
- All fields optional
- `role`: Must be valid role, subject to hierarchy rules
- `email`: Must be valid format, unique
- Admins cannot change role to/from super_admin
- Cannot modify user with equal or higher privilege level

**Response (200 OK):**
```json
{
  "success": true,
  "message": "User updated successfully",
  "user": {
    "id": 3,
    "username": "jane_smith",
    "display_name": "Jane M. Smith",
    "email": "jane.smith@example.com",
    "role": "admin"
  }
}
```

**Errors:**
- `400`: Invalid data, email already exists
- `403`: Cannot manage this user (hierarchy violation)
- `404`: User not found

**Example:**
```bash
curl -X PUT http://localhost:3000/api/users/3 \
  -H "Cookie: token=your-jwt-token" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: your-csrf-token" \
  -d '{
    "displayName": "Jane M. Smith",
    "role": "admin"
  }'
```

---

#### 4. DELETE /api/users/:id

**Description:** Deactivate user account (soft delete)

**Authorization:** `requireSuperAdmin()` - only super admins can delete users

**Response (200 OK):**
```json
{
  "success": true,
  "message": "User deactivated successfully"
}
```

**Errors:**
- `400`: Cannot delete your own account
- `403`: Only super admins can delete users
- `404`: User not found

**Example:**
```bash
curl -X DELETE http://localhost:3000/api/users/3 \
  -H "Cookie: token=your-jwt-token" \
  -H "X-CSRF-Token: your-csrf-token"
```

**Note:** This is a soft delete - sets `is_active = false`. User data is preserved for audit purposes.

---

#### 5. PUT /api/users/:id/password

**Description:** Reset user password (admin function)

**Authorization:** `requireCanManageUser(pool)` - must be able to manage target user

**Request Body:**
```json
{
  "newPassword": "NewSecurePass123!",
  "requireChange": true
}
```

**Validation:**
- `newPassword`: Required, minimum 8 characters
- `requireChange`: Optional boolean, if true user must change password on next login

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset successfully",
  "requireChange": true
}
```

**Errors:**
- `400`: Missing password, password too weak
- `403`: Cannot manage this user
- `404`: User not found

**Example:**
```bash
curl -X PUT http://localhost:3000/api/users/3/password \
  -H "Cookie: token=your-jwt-token" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: your-csrf-token" \
  -d '{
    "newPassword": "NewSecurePass123!",
    "requireChange": true
  }'
```

---

## Middleware

### RBAC Middleware Functions

The RBAC system provides several middleware functions to protect routes.

#### requireRole(roles)

Check if user has one of the required roles.

```javascript
const { requireRole, ROLES } = require('./middleware/rbac');

// Single role
app.get('/api/admin-panel', verifyToken, requireRole(ROLES.ADMIN), (req, res) => {
  res.json({ message: 'Admin only' });
});

// Multiple roles (any match)
app.get('/api/management', verifyToken, requireRole([ROLES.SUPER_ADMIN, ROLES.ADMIN]), (req, res) => {
  res.json({ message: 'Admin or super admin' });
});
```

**Response on denial (403):**
```json
{
  "error": "Insufficient permissions",
  "message": "You do not have permission to perform this action",
  "required": "admin",
  "current": "user"
}
```

---

#### requirePermission(permissions)

Check if user has one of the required permissions.

```javascript
const { requirePermission, PERMISSIONS } = require('./middleware/rbac');

// Single permission
app.delete('/api/services/:id',
  verifyToken,
  requirePermission(PERMISSIONS.SERVICES_DELETE),
  (req, res) => {
    // Delete service
  }
);

// Multiple permissions (any match)
app.get('/api/admin-data',
  verifyToken,
  requirePermission([PERMISSIONS.USERS_VIEW, PERMISSIONS.AUDIT_VIEW]),
  (req, res) => {
    // Return admin data
  }
);
```

**Response on denial (403):**
```json
{
  "error": "Insufficient permissions",
  "message": "You do not have permission to perform this action",
  "required": "services:delete"
}
```

---

#### requireSuperAdmin()

Convenience middleware for super admin only routes.

```javascript
const { requireSuperAdmin } = require('./middleware/rbac');

app.delete('/api/users/:id', verifyToken, requireSuperAdmin(), (req, res) => {
  // Only super admins can delete users
});
```

---

#### requireAdmin()

Convenience middleware for admin or higher routes.

```javascript
const { requireAdmin } = require('./middleware/rbac');

app.get('/api/users', verifyToken, requireAdmin(), (req, res) => {
  // Admins and super admins can list users
});
```

---

#### requireCanManageUser(pool)

Check if user can manage the target user (respects role hierarchy).

```javascript
const { requireCanManageUser } = require('./middleware/rbac');

app.put('/api/users/:id',
  verifyToken,
  requireCanManageUser(pool),
  (req, res) => {
    // req.targetUser is populated with target user data
    const targetUser = req.targetUser;
    // Update user
  }
);
```

**Checks:**
- Target user exists
- Current user has higher privilege level than target
- Cannot modify yourself for role changes
- Attaches `req.targetUser` for use in handler

---

#### requireSelfOrAdmin()

Allow user to edit their own profile OR require admin permission.

```javascript
const { requireSelfOrAdmin } = require('./middleware/rbac');

app.put('/api/profile/:id',
  verifyToken,
  requireSelfOrAdmin(),
  (req, res) => {
    // User can edit own profile, or admin can edit any profile
  }
);
```

---

#### attachPermissions()

Attach permission helper functions to request object.

```javascript
const { attachPermissions } = require('./middleware/rbac');

app.use(verifyToken);
app.use(attachPermissions());

app.get('/api/dashboard', (req, res) => {
  // Use helper functions
  const canEdit = req.can('services:edit');
  const isAdmin = req.hasRole('admin');
  const canManageUsers = req.hasAnyRole(['super_admin', 'admin']);
  const canManageRole = req.canManage('power_user');

  res.json({
    canEdit,
    isAdmin,
    canManageUsers,
    canManageRole
  });
});
```

**Helper Functions:**
- `req.can(permission)` - Check if user has permission
- `req.hasRole(role)` - Check if user has exact role
- `req.hasAnyRole(roles)` - Check if user has any of the roles
- `req.canManage(targetRole)` - Check if user can manage target role

---

## Permission Checking

### In Middleware (Recommended)

Protect routes using middleware for declarative permission checks:

```javascript
const { requirePermission, PERMISSIONS } = require('./middleware/rbac');

app.post('/api/services',
  verifyToken,
  requirePermission(PERMISSIONS.SERVICES_CREATE),
  validateContentType,
  doubleCsrfProtection,
  async (req, res) => {
    // Permission already verified by middleware
    const service = await createService(req.body);
    res.json(service);
  }
);
```

---

### In Route Handlers (Conditional Logic)

Use helper functions for conditional permission checks:

```javascript
const { checkPermission, PERMISSIONS } = require('./middleware/rbac');

app.get('/api/dashboard', verifyToken, async (req, res) => {
  const data = {
    services: await getServices()
  };

  // Conditionally include admin data
  if (checkPermission(req.user, PERMISSIONS.USERS_VIEW)) {
    data.users = await getUsers();
  }

  // Conditionally include audit data
  if (checkPermission(req.user, [PERMISSIONS.AUDIT_VIEW, PERMISSIONS.AUDIT_EXPORT])) {
    data.auditLogs = await getAuditLogs();
  }

  res.json(data);
});
```

---

### With Role Helpers

Check roles using provided helper functions:

```javascript
const { canManageRole, canModifyUser } = require('./config/permissions');

app.put('/api/users/:id', verifyToken, async (req, res) => {
  const targetUser = await getUserById(req.params.id);

  // Check if current user can manage target user
  if (!canModifyUser(req.user, targetUser)) {
    return res.status(403).json({ error: 'Cannot manage this user' });
  }

  // Check if current user can assign the new role
  if (req.body.role && !canManageRole(req.user.role, req.body.role)) {
    return res.status(403).json({ error: 'Cannot assign this role' });
  }

  // Proceed with update
  await updateUser(req.params.id, req.body);
  res.json({ success: true });
});
```

---

## Protected Endpoints

### Current RBAC Implementation Status

| Endpoint | Method | Protection | Required Permission/Role |
|----------|--------|------------|--------------------------|
| **User Management** |
| /api/users | GET | ✅ | Admin+ (`requireAdmin()`) |
| /api/users | POST | ✅ | `users:create` |
| /api/users/:id | PUT | ✅ | Can manage user |
| /api/users/:id | DELETE | ✅ | Super admin only |
| /api/users/:id/password | PUT | ✅ | Can manage user |
| **Category Management** |
| /api/categories | GET | ❌ | Public (authenticated) |
| /api/categories | POST | ✅ | `categories:create` |
| /api/categories/:id | PUT | ✅ | `categories:edit` |
| /api/categories/:id | DELETE | ✅ | `categories:delete` |
| **Service Management** |
| /api/services | GET | ❌ | Public (authenticated) |
| /api/services | POST | ✅ | `services:create` |
| /api/services/:id | PUT | ✅ | `services:edit` |
| /api/services/:id | DELETE | ✅ | `services:delete` |
| **Dashboard** |
| /api/dashboard/categories | GET | ❌ | Public (authenticated) |
| /api/status | GET | ❌ | Public (authenticated) |
| /api/server-info | GET | ❌ | Public (authenticated) |
| **Settings** |
| /api/change-display-name | POST | ❌ | Public (authenticated) |
| /api/change-password | POST | ❌ | Public (authenticated) |

**Note:** ❌ indicates endpoints that are currently authenticated but not using granular RBAC permissions. These can be enhanced in future updates.

---

## Testing & Validation

### Manual Testing with curl

#### Test User Creation (Admin)

```bash
# Login as admin
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@123456"}' \
  -c cookies.txt

# Get CSRF token
CSRF_TOKEN=$(curl -s http://localhost:3000/api/csrf-token -b cookies.txt | jq -r '.csrfToken')

# Create new user
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b cookies.txt \
  -d '{
    "username": "testuser",
    "password": "TestPass123!",
    "displayName": "Test User",
    "email": "test@example.com",
    "role": "user"
  }'

# Expected: {"success":true,"userId":3,"username":"testuser","message":"User created successfully"}
```

---

#### Test Permission Denial (Regular User)

```bash
# Login as regular user
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"TestPass123!"}' \
  -c cookies-user.txt

# Try to list users (should fail)
curl http://localhost:3000/api/users -b cookies-user.txt

# Expected: {"error":"Insufficient permissions","message":"You do not have permission to perform this action"}
```

---

#### Test Service Management Permissions

```bash
# Login as power user
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"poweruser","password":"PowerPass123!"}' \
  -c cookies-power.txt

# View services (should succeed)
curl http://localhost:3000/api/services -b cookies-power.txt

# Get CSRF token
CSRF_TOKEN=$(curl -s http://localhost:3000/api/csrf-token -b cookies-power.txt | jq -r '.csrfToken')

# Delete service (should succeed - power users can delete services)
curl -X DELETE http://localhost:3000/api/services/5 \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b cookies-power.txt

# Expected: {"success":true,"message":"Service deleted successfully"}
```

---

#### Test Role Hierarchy

```bash
# Admin tries to create super admin (should fail)
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b cookies.txt \
  -d '{
    "username": "newsuperadmin",
    "password": "SuperPass123!",
    "role": "super_admin"
  }'

# Expected: {"error":"Cannot create user with higher privilege level than yourself"}

# Super admin tries same (should succeed)
# Login as super admin first
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"superadmin","password":"SuperPass123!"}' \
  -c cookies-super.txt

CSRF_TOKEN=$(curl -s http://localhost:3000/api/csrf-token -b cookies-super.txt | jq -r '.csrfToken')

curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b cookies-super.txt \
  -d '{
    "username": "newsuperadmin",
    "password": "SuperPass123!",
    "role": "super_admin"
  }'

# Expected: {"success":true,"userId":4,"username":"newsuperadmin","message":"User created successfully"}
```

---

### Automated Testing

#### Test Script: test-rbac.sh

```bash
#!/bin/bash

BASE_URL="http://localhost:3000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "=== RBAC Test Suite ==="
echo

# Test 1: Regular user cannot list users
echo "Test 1: Regular user denied /api/users"
curl -s -X POST "$BASE_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"UserPass123!"}' \
  -c cookies-test.txt > /dev/null

RESULT=$(curl -s "$BASE_URL/api/users" -b cookies-test.txt | jq -r '.error')
if [ "$RESULT" == "Insufficient permissions" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Regular user denied"
else
  echo -e "${RED}✗ FAIL${NC}: Regular user should be denied"
fi
echo

# Test 2: Regular user can view services
echo "Test 2: Regular user can view services"
RESULT=$(curl -s "$BASE_URL/api/services" -b cookies-test.txt | jq -r 'type')
if [ "$RESULT" == "object" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Regular user can view services"
else
  echo -e "${RED}✗ FAIL${NC}: Regular user should view services"
fi
echo

# Test 3: Regular user cannot delete services
echo "Test 3: Regular user denied service deletion"
CSRF_TOKEN=$(curl -s "$BASE_URL/api/csrf-token" -b cookies-test.txt | jq -r '.csrfToken')
RESULT=$(curl -s -X DELETE "$BASE_URL/api/services/1" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b cookies-test.txt | jq -r '.error')
if [ "$RESULT" == "Insufficient permissions" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Regular user denied service deletion"
else
  echo -e "${RED}✗ FAIL${NC}: Regular user should be denied"
fi
echo

# Test 4: Admin can list users
echo "Test 4: Admin can list users"
curl -s -X POST "$BASE_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@123456"}' \
  -c cookies-admin.txt > /dev/null

RESULT=$(curl -s "$BASE_URL/api/users" -b cookies-admin.txt | jq -r 'type')
if [ "$RESULT" == "array" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Admin can list users"
else
  echo -e "${RED}✗ FAIL${NC}: Admin should list users"
fi
echo

# Test 5: Power user can delete services
echo "Test 5: Power user can delete services"
curl -s -X POST "$BASE_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"poweruser","password":"PowerPass123!"}' \
  -c cookies-power.txt > /dev/null

CSRF_TOKEN=$(curl -s "$BASE_URL/api/csrf-token" -b cookies-power.txt | jq -r '.csrfToken')
# Note: Using a non-existent service ID to avoid actually deleting services
RESULT=$(curl -s -X DELETE "$BASE_URL/api/services/9999" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b cookies-power.txt | jq -r '.error // "allowed"')
if [ "$RESULT" != "Insufficient permissions" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Power user can attempt service deletion"
else
  echo -e "${RED}✗ FAIL${NC}: Power user should be allowed"
fi
echo

# Cleanup
rm -f cookies-*.txt

echo "=== Test Suite Complete ==="
```

**Run tests:**
```bash
chmod +x test-rbac.sh
./test-rbac.sh
```

---

## Security Features

### 1. Role Hierarchy Enforcement

**Protection Against Privilege Escalation:**
```javascript
// Admin cannot create or promote to super_admin
if (role === ROLES.SUPER_ADMIN && req.user.role !== ROLES.SUPER_ADMIN) {
  return res.status(403).json({
    error: 'Cannot create user with higher privilege level than yourself'
  });
}

// Admin cannot modify super_admin users
function canModifyUser(actor, target) {
  if (!actor || !target) return false;
  if (actor.id === target.id) return false;
  return canManageRole(actor.role, target.role);
}
```

---

### 2. Self-Modification Protection

**Users Cannot Change Their Own Role or Delete Themselves:**
```javascript
// In PUT /api/users/:id - role changes
if (role !== undefined) {
  if (parseInt(userId) === req.user.id) {
    return res.status(400).json({ error: 'Cannot change your own role' });
  }
  // ... role hierarchy checks
}

// In DELETE /api/users/:id
if (parseInt(userId) === req.user.id) {
  return res.status(400).json({ error: 'Cannot delete your own account' });
}
```

---

### 3. Permission-Based Access Control

**Granular Permissions Beyond Roles:**
```javascript
// Check both role-based and custom permissions
function userHasPermission(user, permission) {
  // Check role-based permissions first
  if (hasPermission(user.role, permission)) {
    return true;
  }

  // Check custom permissions (JSONB array)
  if (user.permissions && Array.isArray(user.permissions)) {
    return user.permissions.includes(permission);
  }

  return false;
}
```

**Use Case:** Grant temporary permissions without changing role
```sql
-- Grant specific user extra permission
UPDATE users
SET permissions = permissions || '["services:delete"]'::jsonb
WHERE id = 5;
```

---

### 4. Soft Delete

**Preserve Data Integrity:**
```javascript
// DELETE /api/users/:id - soft delete only
const result = await pool.query(`
  UPDATE users
  SET is_active = false, updated_at = NOW()
  WHERE id = $1
  RETURNING username
`, [userId]);
```

**Benefits:**
- User data preserved for audit trails
- Can be reactivated if needed
- Foreign key references remain valid
- Historical records stay intact

---

### 5. Middleware-Based Protection

**Declarative Security Model:**
```javascript
// Clear, auditable security declarations
app.post('/api/users',
  verifyToken,                              // Authentication
  requirePermission(PERMISSIONS.USERS_CREATE), // Authorization
  validateContentType,                      // Input validation
  doubleCsrfProtection,                     // CSRF protection
  async (req, res) => {
    // Business logic only - security handled by middleware
  }
);
```

**Advantages:**
- Security logic centralized
- Easy to audit
- Consistent across endpoints
- Less prone to errors

---

## Configuration

### Defining Roles

Roles are defined in `/opt/dashboard/config/permissions.js`:

```javascript
const ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  POWER_USER: 'power_user',
  USER: 'user',
  READ_ONLY: 'read_only'
};

const ROLE_LEVELS = {
  [ROLES.SUPER_ADMIN]: 100,
  [ROLES.ADMIN]: 80,
  [ROLES.POWER_USER]: 60,
  [ROLES.USER]: 40,
  [ROLES.READ_ONLY]: 20
};
```

**Adding a New Role:**
1. Add to ROLES object
2. Add privilege level to ROLE_LEVELS
3. Define permissions in ROLE_PERMISSIONS
4. Update database constraint if needed:
   ```sql
   ALTER TABLE users DROP CONSTRAINT valid_role;
   ALTER TABLE users ADD CONSTRAINT valid_role
     CHECK (role IN ('super_admin', 'admin', 'power_user', 'user', 'read_only', 'new_role'));
   ```

---

### Defining Permissions

Permissions are defined in `/opt/dashboard/config/permissions.js`:

```javascript
const PERMISSIONS = {
  // User management
  USERS_VIEW: 'users:view',
  USERS_CREATE: 'users:create',
  USERS_EDIT: 'users:edit',
  USERS_DELETE: 'users:delete',
  USERS_CHANGE_ROLE: 'users:change_role',

  // ... other categories
};
```

**Adding a New Permission:**
1. Add to PERMISSIONS object with descriptive name
2. Use format `category:action` (e.g., `reports:export`)
3. Add to appropriate roles in ROLE_PERMISSIONS:
   ```javascript
   const ROLE_PERMISSIONS = {
     [ROLES.SUPER_ADMIN]: [
       // ... existing permissions
       PERMISSIONS.REPORTS_EXPORT,  // New permission
     ],
     // ... other roles
   };
   ```
4. Use in middleware:
   ```javascript
   app.get('/api/reports/export',
     verifyToken,
     requirePermission(PERMISSIONS.REPORTS_EXPORT),
     exportReports
   );
   ```

---

### Custom User Permissions

Beyond role-based permissions, users can have custom permissions stored in JSONB:

**Database Schema:**
```sql
-- users table has JSONB permissions column
permissions JSONB DEFAULT '[]'::JSONB
```

**Granting Custom Permission:**
```sql
-- Add permission to user
UPDATE users
SET permissions = permissions || '["services:delete", "audit:view"]'::jsonb
WHERE id = 10;

-- Remove permission from user
UPDATE users
SET permissions = permissions - 'services:delete'
WHERE id = 10;

-- View user permissions
SELECT username, role, permissions
FROM users
WHERE id = 10;
```

**Example Use Case:**
- User with role `user` normally cannot delete services
- Grant temporary `services:delete` permission for cleanup task
- User retains `user` role but gains specific permission
- Permission can be revoked without role change

---

## Monitoring

### User Activity Tracking

All user management actions are logged to `audit_logs` table (when implemented):

```sql
-- View recent user management actions
SELECT
  timestamp,
  username,
  action,
  resource_type,
  resource_id,
  status,
  ip_address
FROM audit_logs
WHERE action LIKE 'user.%'
ORDER BY timestamp DESC
LIMIT 50;
```

**Example Log Entries:**
```
2025-11-13 15:30:00 | admin | user.create | user | 5 | success | 10.99.0.1
2025-11-13 15:35:00 | admin | user.edit | user | 5 | success | 10.99.0.1
2025-11-13 15:40:00 | john | user.edit | user | 3 | denied | 10.99.0.5
```

---

### Permission Audit

Check which users have specific permissions:

```sql
-- Users with users:delete permission (super_admins)
SELECT username, role
FROM users
WHERE role = 'super_admin'
   OR permissions @> '["users:delete"]'::jsonb;

-- Users who can manage services
SELECT username, role
FROM users
WHERE role IN ('super_admin', 'admin', 'power_user')
   OR permissions @> '["services:edit"]'::jsonb
   OR permissions @> '["services:delete"]'::jsonb;

-- Users with custom permissions
SELECT username, role, permissions
FROM users
WHERE jsonb_array_length(permissions) > 0;
```

---

### Role Distribution

Monitor role distribution across users:

```sql
-- Count users by role
SELECT
  role,
  COUNT(*) as user_count,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM users
WHERE is_active = true
GROUP BY role
ORDER BY user_count DESC;
```

**Example Output:**
```
role         | user_count | percentage
-------------|------------|------------
user         | 45         | 75.00
power_user   | 10         | 16.67
admin        | 4          | 6.67
super_admin  | 1          | 1.67
read_only    | 0          | 0.00
```

---

### Failed Permission Attempts

Track permission denials (requires audit logging):

```sql
-- Most denied actions
SELECT
  action,
  COUNT(*) as denial_count,
  COUNT(DISTINCT user_id) as affected_users
FROM audit_logs
WHERE status = 'denied'
  AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY action
ORDER BY denial_count DESC
LIMIT 10;
```

---

## Troubleshooting

### Permission Denied Errors

**Error:** "Insufficient permissions" when accessing endpoint

**Solutions:**

1. **Check User Role:**
   ```sql
   SELECT username, role, permissions
   FROM users
   WHERE username = 'john_doe';
   ```

2. **Verify Required Permission:**
   - Check middleware in server.js for the endpoint
   - Example: `requirePermission(PERMISSIONS.SERVICES_DELETE)`
   - Check if user's role has this permission in `config/permissions.js`

3. **Check JWT Token:**
   ```bash
   # Decode JWT to see user data
   echo "your-jwt-token" | cut -d'.' -f2 | base64 -d | jq
   ```
   Verify the `role` field in the token matches database.

4. **Check Custom Permissions:**
   ```sql
   SELECT permissions
   FROM users
   WHERE username = 'john_doe';
   ```
   If empty, user relies only on role-based permissions.

---

### Role Hierarchy Issues

**Error:** "Cannot manage this user"

**Cause:** Trying to modify user with equal or higher privilege level

**Solutions:**

1. **Check Role Levels:**
   ```sql
   SELECT
     actor.username as actor,
     actor.role as actor_role,
     target.username as target,
     target.role as target_role
   FROM users actor, users target
   WHERE actor.id = 2 AND target.id = 5;
   ```

2. **Verify Role Hierarchy:**
   - Super admin (100) > Admin (80) > Power user (60) > User (40) > Read only (20)
   - Actors can only manage lower-level users

3. **Use Correct Account:**
   - Use super_admin to manage admin users
   - Admins cannot manage other admins or super_admins

---

### User Cannot Change Role

**Error:** "Cannot change your own role"

**Cause:** Users are prevented from self-elevation

**Solution:** Use a different admin account to change the role:
```bash
# Login as different admin
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin2","password":"password"}' \
  -c cookies.txt

# Change target user's role
curl -X PUT http://localhost:3000/api/users/5 \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b cookies.txt \
  -d '{"role":"power_user"}'
```

---

### Admin Cannot Create Super Admin

**Error:** "Cannot create user with higher privilege level than yourself"

**Cause:** Only super_admins can create other super_admins

**Solution:** Login as super_admin or promote via database:
```sql
-- Temporary promotion (for creating super admin)
UPDATE users SET role = 'super_admin' WHERE username = 'admin';

-- Create super admin via API

-- Demote back if needed
UPDATE users SET role = 'admin' WHERE username = 'admin';
```

**Better Approach:** Use existing super_admin account or create via database:
```sql
INSERT INTO users (username, password, role, is_active)
VALUES (
  'newsuperadmin',
  '$2a$10$hashedpassword',  -- Use bcryptjs.hashSync('password', 10)
  'super_admin',
  true
);
```

---

### Middleware Order Issues

**Error:** `req.user` is undefined in RBAC middleware

**Cause:** RBAC middleware called before `verifyToken`

**Solution:** Ensure correct middleware order:
```javascript
// ❌ WRONG - RBAC before auth
app.get('/api/users', requireAdmin(), verifyToken, handler);

// ✅ CORRECT - Auth before RBAC
app.get('/api/users', verifyToken, requireAdmin(), handler);

// ✅ CORRECT - Full stack
app.post('/api/services',
  verifyToken,                    // 1. Authentication
  requirePermission(PERMISSIONS.SERVICES_CREATE), // 2. Authorization
  validateContentType,            // 3. Input validation
  doubleCsrfProtection,          // 4. CSRF protection
  handler                        // 5. Business logic
);
```

---

## Best Practices

### 1. Always Use Middleware for Authorization

```javascript
// ❌ BAD: Manual permission checks in every handler
app.post('/api/services', verifyToken, async (req, res) => {
  if (!userHasPermission(req.user, PERMISSIONS.SERVICES_CREATE)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  // ... business logic
});

// ✅ GOOD: Declarative middleware
app.post('/api/services',
  verifyToken,
  requirePermission(PERMISSIONS.SERVICES_CREATE),
  async (req, res) => {
    // ... business logic only
  }
);
```

---

### 2. Use Specific Permissions, Not Roles

```javascript
// ❌ BAD: Checking roles directly
if (req.user.role === 'admin' || req.user.role === 'super_admin') {
  // Allow action
}

// ✅ GOOD: Checking permissions
if (req.can(PERMISSIONS.SERVICES_DELETE)) {
  // Allow action
}
```

**Why:** Permissions allow role-independent access control and easier policy changes.

---

### 3. Respect Role Hierarchy

```javascript
// ✅ GOOD: Always check hierarchy for user management
if (!canModifyUser(req.user, targetUser)) {
  return res.status(403).json({ error: 'Cannot manage this user' });
}

// ✅ GOOD: Use requireCanManageUser middleware
app.put('/api/users/:id',
  verifyToken,
  requireCanManageUser(pool),
  handler
);
```

---

### 4. Use Soft Deletes

```javascript
// ❌ BAD: Hard delete loses audit trail
await pool.query('DELETE FROM users WHERE id = $1', [userId]);

// ✅ GOOD: Soft delete preserves history
await pool.query(`
  UPDATE users
  SET is_active = false, updated_at = NOW()
  WHERE id = $1
`, [userId]);
```

---

### 5. Log All Permission Changes

```javascript
// ✅ GOOD: Audit user role changes
const oldRole = targetUser.role;
const newRole = req.body.role;

await pool.query('UPDATE users SET role = $1 WHERE id = $2', [newRole, userId]);

await pool.query(
  'SELECT log_audit_event($1, $2, $3, $4, $5, $6, $7, $8, $9)',
  [
    req.user.id,
    'user.role_change',
    'user',
    userId,
    JSON.stringify({ before: { role: oldRole }, after: { role: newRole } }),
    JSON.stringify({ changedBy: req.user.username }),
    'success',
    req.ip,
    req.headers['user-agent']
  ]
);
```

---

### 6. Validate Role Values

```javascript
// ✅ GOOD: Validate role before database insert
const validRoles = ['super_admin', 'admin', 'power_user', 'user', 'read_only'];
if (role && !validRoles.includes(role)) {
  return res.status(400).json({ error: 'Invalid role' });
}
```

---

### 7. Use Type-Safe Permission Constants

```javascript
// ❌ BAD: Magic strings
if (req.can('services:delete')) { }

// ✅ GOOD: Constants prevent typos
const { PERMISSIONS } = require('./middleware/rbac');
if (req.can(PERMISSIONS.SERVICES_DELETE)) { }
```

---

### 8. Provide Clear Error Messages

```javascript
// ❌ BAD: Generic error
return res.status(403).json({ error: 'Forbidden' });

// ✅ GOOD: Helpful error message
return res.status(403).json({
  error: 'Insufficient permissions',
  message: 'You do not have permission to perform this action',
  required: 'services:delete',
  current: req.user.role
});
```

---

## Future Enhancements

### 1. API Key Authentication

**Status:** Schema ready, implementation pending

**Features:**
- API keys for service-to-service authentication
- Per-key permissions (JSONB)
- Rate limiting per API key
- Expiration and revocation support

**Schema:**
```sql
CREATE TABLE api_keys (
  id SERIAL PRIMARY KEY,
  key_hash VARCHAR(255) UNIQUE NOT NULL,
  key_prefix VARCHAR(10) NOT NULL,
  name VARCHAR(100) NOT NULL,
  user_id INTEGER REFERENCES users(id),
  permissions JSONB DEFAULT '[]'::JSONB,
  rate_limit INTEGER DEFAULT 100,
  is_active BOOLEAN DEFAULT TRUE,
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

**Example Usage:**
```bash
# Create API key
curl -X POST http://localhost:3000/api/api-keys \
  -H "Cookie: token=admin-jwt" \
  -d '{
    "name": "Automation Script",
    "permissions": ["services:view", "status:view"],
    "expiresAt": "2026-01-01T00:00:00Z"
  }'

# Response
{
  "apiKey": "dash_k7h3j9d8s...",  # Full key shown once
  "keyId": 15,
  "keyPrefix": "dash_k7h3"
}

# Use API key
curl http://localhost:3000/api/services \
  -H "X-API-Key: dash_k7h3j9d8s..."
```

---

### 2. Audit Logging UI

**Status:** Backend ready, frontend pending

**Features:**
- View all user actions
- Filter by user, action, date range
- Export audit logs
- Real-time activity feed

**Example API:**
```bash
# Get audit logs
GET /api/audit/logs?user=5&action=user.create&from=2025-11-01&to=2025-11-13

# Export audit logs
GET /api/audit/export?format=csv
```

**UI Components:**
- Audit log table with pagination
- Advanced filters (user, action, resource, date)
- Export button (CSV, JSON)
- Live activity feed (WebSocket)

---

### 3. Advanced Permission Scopes

**Status:** Design phase

**Features:**
- Resource-level permissions (e.g., can edit only services in category X)
- Time-based permissions (temporary elevated access)
- Conditional permissions (e.g., can edit if created_by = user)

**Example:**
```javascript
// Resource-scoped permission
const canEdit = req.can('services:edit', { category: 'content-management' });

// Time-based permission
await grantTemporaryPermission(userId, 'services:delete', { expiresAt: '2025-11-14T00:00:00Z' });

// Conditional permission
const canEdit = req.can('services:edit', { where: { created_by: req.user.id } });
```

---

### 4. Multi-Tenancy Support

**Status:** Design phase

**Features:**
- Organization/tenant isolation
- Per-tenant role definitions
- Cross-tenant super admin
- Tenant-specific permissions

**Schema Changes:**
```sql
CREATE TABLE tenants (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  is_active BOOLEAN DEFAULT TRUE
);

ALTER TABLE users ADD COLUMN tenant_id INTEGER REFERENCES tenants(id);
ALTER TABLE services ADD COLUMN tenant_id INTEGER REFERENCES tenants(id);
```

---

### 5. Permission Groups

**Status:** Design phase

**Features:**
- Group permissions into reusable sets
- Assign permission groups to users
- Easier management than individual permissions

**Example:**
```javascript
const PERMISSION_GROUPS = {
  SERVICE_MANAGER: [
    PERMISSIONS.SERVICES_VIEW,
    PERMISSIONS.SERVICES_CREATE,
    PERMISSIONS.SERVICES_EDIT,
    PERMISSIONS.CATEGORIES_VIEW
  ],
  AUDITOR: [
    PERMISSIONS.AUDIT_VIEW,
    PERMISSIONS.AUDIT_EXPORT,
    PERMISSIONS.USERS_VIEW
  ]
};

// Assign group to user
await assignPermissionGroup(userId, 'SERVICE_MANAGER');
```

---

## Conclusion

Phase 3 (RBAC Integration) successfully delivers enterprise-grade access control:

1. ✅ **5-tier role hierarchy** with clear privilege levels
2. ✅ **20+ granular permissions** across 6 categories
3. ✅ **5 user management endpoints** for complete user lifecycle
4. ✅ **Middleware-based protection** for declarative security
5. ✅ **Role hierarchy enforcement** prevents privilege escalation
6. ✅ **Permission-based access control** beyond simple roles
7. ✅ **Soft delete support** preserves audit trails
8. ✅ **Custom user permissions** via JSONB for flexibility

The application now supports true multi-user deployments with fine-grained access control, ready for enterprise environments with diverse user roles and responsibilities.

**Implementation Metrics:**
- 5 roles defined with clear hierarchy
- 20 permissions across 6 categories
- 5 user management API endpoints
- 8 middleware functions for protection
- 12+ helper functions for permission checking
- Full PostgreSQL schema with constraints
- Comprehensive error messages and validation
- Production-ready security controls

**Next Phase:** Audit Logging & Monitoring (Phase 4)
