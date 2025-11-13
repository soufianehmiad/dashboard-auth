/**
 * RBAC Permission Model
 *
 * Defines the role hierarchy and permission structure for the dashboard application.
 */

// Role hierarchy (in order of privilege)
const ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  POWER_USER: 'power_user',
  USER: 'user',
  READ_ONLY: 'read_only'
};

// Role hierarchy levels (higher number = more privilege)
const ROLE_LEVELS = {
  [ROLES.SUPER_ADMIN]: 100,
  [ROLES.ADMIN]: 80,
  [ROLES.POWER_USER]: 60,
  [ROLES.USER]: 40,
  [ROLES.READ_ONLY]: 20
};

// Permission categories
const PERMISSIONS = {
  // User management
  USERS_VIEW: 'users:view',
  USERS_CREATE: 'users:create',
  USERS_EDIT: 'users:edit',
  USERS_DELETE: 'users:delete',
  USERS_CHANGE_ROLE: 'users:change_role',

  // Service management
  SERVICES_VIEW: 'services:view',
  SERVICES_CREATE: 'services:create',
  SERVICES_EDIT: 'services:edit',
  SERVICES_DELETE: 'services:delete',

  // Category management
  CATEGORIES_VIEW: 'categories:view',
  CATEGORIES_CREATE: 'categories:create',
  CATEGORIES_EDIT: 'categories:edit',
  CATEGORIES_DELETE: 'categories:delete',

  // API key management
  API_KEYS_VIEW: 'api_keys:view',
  API_KEYS_CREATE: 'api_keys:create',
  API_KEYS_REVOKE: 'api_keys:revoke',

  // System settings
  SETTINGS_VIEW: 'settings:view',
  SETTINGS_EDIT: 'settings:edit',

  // Audit logs
  AUDIT_VIEW: 'audit:view',
  AUDIT_EXPORT: 'audit:export'
};

// Role-based permissions matrix
const ROLE_PERMISSIONS = {
  [ROLES.SUPER_ADMIN]: [
    // Full access to everything
    PERMISSIONS.USERS_VIEW,
    PERMISSIONS.USERS_CREATE,
    PERMISSIONS.USERS_EDIT,
    PERMISSIONS.USERS_DELETE,
    PERMISSIONS.USERS_CHANGE_ROLE,
    PERMISSIONS.SERVICES_VIEW,
    PERMISSIONS.SERVICES_CREATE,
    PERMISSIONS.SERVICES_EDIT,
    PERMISSIONS.SERVICES_DELETE,
    PERMISSIONS.CATEGORIES_VIEW,
    PERMISSIONS.CATEGORIES_CREATE,
    PERMISSIONS.CATEGORIES_EDIT,
    PERMISSIONS.CATEGORIES_DELETE,
    PERMISSIONS.API_KEYS_VIEW,
    PERMISSIONS.API_KEYS_CREATE,
    PERMISSIONS.API_KEYS_REVOKE,
    PERMISSIONS.SETTINGS_VIEW,
    PERMISSIONS.SETTINGS_EDIT,
    PERMISSIONS.AUDIT_VIEW,
    PERMISSIONS.AUDIT_EXPORT
  ],

  [ROLES.ADMIN]: [
    // Can manage users (except super_admins), services, categories
    PERMISSIONS.USERS_VIEW,
    PERMISSIONS.USERS_CREATE,
    PERMISSIONS.USERS_EDIT,
    // USERS_DELETE excluded - only super_admin can delete
    // USERS_CHANGE_ROLE excluded for super_admin promotions
    PERMISSIONS.SERVICES_VIEW,
    PERMISSIONS.SERVICES_CREATE,
    PERMISSIONS.SERVICES_EDIT,
    PERMISSIONS.SERVICES_DELETE,
    PERMISSIONS.CATEGORIES_VIEW,
    PERMISSIONS.CATEGORIES_CREATE,
    PERMISSIONS.CATEGORIES_EDIT,
    PERMISSIONS.CATEGORIES_DELETE,
    PERMISSIONS.API_KEYS_VIEW,
    PERMISSIONS.API_KEYS_CREATE,
    PERMISSIONS.API_KEYS_REVOKE,
    PERMISSIONS.SETTINGS_VIEW,
    PERMISSIONS.AUDIT_VIEW
  ],

  [ROLES.POWER_USER]: [
    // Can manage services and categories, view users
    PERMISSIONS.USERS_VIEW,
    PERMISSIONS.SERVICES_VIEW,
    PERMISSIONS.SERVICES_CREATE,
    PERMISSIONS.SERVICES_EDIT,
    PERMISSIONS.SERVICES_DELETE,
    PERMISSIONS.CATEGORIES_VIEW,
    PERMISSIONS.CATEGORIES_CREATE,
    PERMISSIONS.CATEGORIES_EDIT,
    PERMISSIONS.CATEGORIES_DELETE,
    PERMISSIONS.API_KEYS_VIEW,
    PERMISSIONS.SETTINGS_VIEW
  ],

  [ROLES.USER]: [
    // Can view everything, edit own profile, create services/categories
    PERMISSIONS.USERS_VIEW,
    PERMISSIONS.SERVICES_VIEW,
    PERMISSIONS.SERVICES_CREATE,
    PERMISSIONS.CATEGORIES_VIEW,
    PERMISSIONS.CATEGORIES_CREATE,
    PERMISSIONS.SETTINGS_VIEW
  ],

  [ROLES.READ_ONLY]: [
    // Can only view
    PERMISSIONS.SERVICES_VIEW,
    PERMISSIONS.CATEGORIES_VIEW,
    PERMISSIONS.SETTINGS_VIEW
  ]
};

/**
 * Check if a role has a specific permission
 * @param {string} role - User role
 * @param {string} permission - Permission to check
 * @returns {boolean}
 */
function hasPermission(role, permission) {
  if (!role || !ROLE_PERMISSIONS[role]) {
    return false;
  }
  return ROLE_PERMISSIONS[role].includes(permission);
}

/**
 * Check if a user has a specific permission (role + custom permissions)
 * @param {Object} user - User object with role and permissions fields
 * @param {string} permission - Permission to check
 * @returns {boolean}
 */
function userHasPermission(user, permission) {
  if (!user) return false;

  // Check role-based permissions
  if (hasPermission(user.role, permission)) {
    return true;
  }

  // Check custom permissions (JSONB array)
  if (user.permissions && Array.isArray(user.permissions)) {
    return user.permissions.includes(permission);
  }

  return false;
}

/**
 * Check if role A can manage role B
 * @param {string} roleA - Managing role
 * @param {string} roleB - Target role
 * @returns {boolean}
 */
function canManageRole(roleA, roleB) {
  // Super admin can manage everyone
  if (roleA === ROLES.SUPER_ADMIN) return true;

  // Admins can manage everyone except super_admins
  if (roleA === ROLES.ADMIN && roleB !== ROLES.SUPER_ADMIN) return true;

  // Others can't manage users
  return false;
}

/**
 * Get all permissions for a role
 * @param {string} role - User role
 * @returns {string[]}
 */
function getRolePermissions(role) {
  return ROLE_PERMISSIONS[role] || [];
}

/**
 * Check if user can perform action on target user
 * @param {Object} actor - User performing action
 * @param {Object} target - User being acted upon
 * @returns {boolean}
 */
function canModifyUser(actor, target) {
  if (!actor || !target) return false;

  // Can't modify yourself for role changes or deletion
  if (actor.id === target.id) return false;

  // Check if actor can manage target's role
  return canManageRole(actor.role, target.role);
}

/**
 * Get role display name
 * @param {string} role - Role key
 * @returns {string}
 */
function getRoleDisplayName(role) {
  const displayNames = {
    [ROLES.SUPER_ADMIN]: 'Super Administrator',
    [ROLES.ADMIN]: 'Administrator',
    [ROLES.POWER_USER]: 'Power User',
    [ROLES.USER]: 'User',
    [ROLES.READ_ONLY]: 'Read Only'
  };
  return displayNames[role] || role;
}

/**
 * Get role description
 * @param {string} role - Role key
 * @returns {string}
 */
function getRoleDescription(role) {
  const descriptions = {
    [ROLES.SUPER_ADMIN]: 'Full system access, can manage all users including other admins',
    [ROLES.ADMIN]: 'Can manage users, services, and categories (except super admins)',
    [ROLES.POWER_USER]: 'Can manage services and categories, view users',
    [ROLES.USER]: 'Can view and create services/categories, edit own profile',
    [ROLES.READ_ONLY]: 'Can only view services and categories'
  };
  return descriptions[role] || '';
}

/**
 * Get all available roles for a user to assign
 * @param {string} userRole - Current user's role
 * @returns {Object[]}
 */
function getAssignableRoles(userRole) {
  const allRoles = Object.values(ROLES).map(role => ({
    value: role,
    label: getRoleDisplayName(role),
    description: getRoleDescription(role),
    level: ROLE_LEVELS[role]
  }));

  if (userRole === ROLES.SUPER_ADMIN) {
    // Super admins can assign any role
    return allRoles;
  }

  if (userRole === ROLES.ADMIN) {
    // Admins can assign any role except super_admin
    return allRoles.filter(r => r.value !== ROLES.SUPER_ADMIN);
  }

  // Others can't assign roles
  return [];
}

module.exports = {
  ROLES,
  ROLE_LEVELS,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  hasPermission,
  userHasPermission,
  canManageRole,
  canModifyUser,
  getRolePermissions,
  getRoleDisplayName,
  getRoleDescription,
  getAssignableRoles
};
