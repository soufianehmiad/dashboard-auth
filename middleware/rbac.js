/**
 * RBAC Middleware
 *
 * Provides role-based and permission-based access control for API endpoints.
 */

const {
  ROLES,
  ROLE_LEVELS,
  PERMISSIONS,
  hasPermission,
  userHasPermission,
  canManageRole,
  canModifyUser
} = require('../config/permissions');

/**
 * Middleware to check if user has required role
 * @param {string|string[]} requiredRoles - Required role(s)
 * @returns {Function} Express middleware
 */
function requireRole(requiredRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userRole = req.user.role;
    const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

    // Check if user has any of the required roles
    if (roles.includes(userRole)) {
      return next();
    }

    // Check if user's role level is high enough
    const userLevel = ROLE_LEVELS[userRole] || 0;
    const requiredLevel = Math.max(...roles.map(r => ROLE_LEVELS[r] || 0));

    if (userLevel >= requiredLevel) {
      return next();
    }

    return res.status(403).json({
      error: 'Insufficient permissions',
      message: 'You do not have permission to perform this action',
      required: roles.length === 1 ? roles[0] : roles,
      current: userRole
    });
  };
}

/**
 * Middleware to check if user has required permission
 * @param {string|string[]} requiredPermissions - Required permission(s)
 * @returns {Function} Express middleware
 */
function requirePermission(requiredPermissions) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const permissions = Array.isArray(requiredPermissions) ? requiredPermissions : [requiredPermissions];

    // Check if user has any of the required permissions
    const hasAnyPermission = permissions.some(permission =>
      userHasPermission(req.user, permission)
    );

    if (hasAnyPermission) {
      return next();
    }

    return res.status(403).json({
      error: 'Insufficient permissions',
      message: 'You do not have permission to perform this action',
      required: permissions.length === 1 ? permissions[0] : permissions
    });
  };
}

/**
 * Middleware to check if user is super admin
 * @returns {Function} Express middleware
 */
function requireSuperAdmin() {
  return requireRole(ROLES.SUPER_ADMIN);
}

/**
 * Middleware to check if user is admin or higher
 * @returns {Function} Express middleware
 */
function requireAdmin() {
  return requireRole([ROLES.SUPER_ADMIN, ROLES.ADMIN]);
}

/**
 * Middleware to check if user can manage target user
 * Target user ID should be in req.params.id or req.params.userId
 * @param {Object} pool - PostgreSQL pool
 * @returns {Function} Express middleware
 */
function requireCanManageUser(pool) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const targetUserId = req.params.id || req.params.userId;
    if (!targetUserId) {
      return res.status(400).json({ error: 'User ID required' });
    }

    try {
      // Fetch target user
      const result = await pool.query(
        'SELECT id, username, role FROM users WHERE id = $1',
        [targetUserId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const targetUser = result.rows[0];

      // Check if current user can modify target user
      if (!canModifyUser(req.user, targetUser)) {
        return res.status(403).json({
          error: 'Insufficient permissions',
          message: 'You cannot manage this user'
        });
      }

      // Attach target user to request for later use
      req.targetUser = targetUser;
      next();
    } catch (err) {
      console.error('Error checking user management permission:', err);
      return res.status(500).json({ error: 'Failed to verify permissions' });
    }
  };
}

/**
 * Middleware to allow user to edit their own profile OR require admin
 * @returns {Function} Express middleware
 */
function requireSelfOrAdmin() {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const targetUserId = parseInt(req.params.id || req.params.userId);
    const currentUserId = req.user.id;

    // Allow if editing self
    if (targetUserId === currentUserId) {
      return next();
    }

    // Otherwise require admin
    const userRole = req.user.role;
    if ([ROLES.SUPER_ADMIN, ROLES.ADMIN].includes(userRole)) {
      return next();
    }

    return res.status(403).json({
      error: 'Insufficient permissions',
      message: 'You can only edit your own profile'
    });
  };
}

/**
 * Middleware to attach user permissions to request
 * Call this after verifyToken to add permission checking helpers
 * @returns {Function} Express middleware
 */
function attachPermissions() {
  return (req, res, next) => {
    if (req.user) {
      // Add permission checking helpers to request
      req.can = (permission) => userHasPermission(req.user, permission);
      req.hasRole = (role) => req.user.role === role;
      req.hasAnyRole = (roles) => roles.includes(req.user.role);
      req.canManage = (targetRole) => canManageRole(req.user.role, targetRole);
    }
    next();
  };
}

/**
 * Middleware factory to create role-specific rate limiters
 * @param {Object} limits - Rate limits per role (requests per window)
 * @param {number} windowMs - Time window in milliseconds
 * @returns {Function} Express middleware
 */
function roleBasedRateLimit(limits, windowMs = 60000) {
  return (req, res, next) => {
    if (!req.user) {
      return next(); // Let auth middleware handle this
    }

    const userRole = req.user.role;
    const limit = limits[userRole] || limits.default || 100;

    // Store in req for rate limiter to use
    req.rateLimit = {
      max: limit,
      windowMs: windowMs
    };

    next();
  };
}

/**
 * Helper to check permissions in route handlers
 * @param {Object} user - User object
 * @param {string|string[]} permissions - Required permission(s)
 * @returns {boolean}
 */
function checkPermission(user, permissions) {
  if (!user) return false;

  const perms = Array.isArray(permissions) ? permissions : [permissions];
  return perms.some(permission => userHasPermission(user, permission));
}

/**
 * Helper to check if user has role
 * @param {Object} user - User object
 * @param {string|string[]} roles - Required role(s)
 * @returns {boolean}
 */
function checkRole(user, roles) {
  if (!user) return false;

  const roleList = Array.isArray(roles) ? roles : [roles];
  return roleList.includes(user.role);
}

module.exports = {
  requireRole,
  requirePermission,
  requireSuperAdmin,
  requireAdmin,
  requireCanManageUser,
  requireSelfOrAdmin,
  attachPermissions,
  roleBasedRateLimit,
  checkPermission,
  checkRole,
  ROLES,
  PERMISSIONS
};
