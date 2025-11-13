// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const path = require('path');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const { execFile } = require('child_process');
const util = require('util');
const execFilePromise = util.promisify(execFile);
const crypto = require('crypto');
const helmet = require('helmet');
const { doubleCsrf } = require('csrf-csrf');
const { createClient } = require('redis');
const { RedisStore } = require('rate-limit-redis');
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

const app = express();
const PORT = 3000;

// SECURITY: Validate JWT_SECRET at startup
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === 'change-this-secret-key-in-production') {
  console.error('╔════════════════════════════════════════════════════════════╗');
  console.error('║ CRITICAL ERROR: JWT_SECRET not configured                 ║');
  console.error('║                                                            ║');
  console.error('║ Set a secure random value in your .env file:              ║');
  console.error('║   JWT_SECRET=<your-random-secret>                         ║');
  console.error('║                                                            ║');
  console.error('║ Generate one with:                                        ║');
  console.error('║   openssl rand -base64 32                                 ║');
  console.error('╚════════════════════════════════════════════════════════════╝');
  process.exit(1);
}

if (JWT_SECRET.length < 32) {
  console.error('ERROR: JWT_SECRET must be at least 32 characters long');
  console.error('Generate a secure one with: openssl rand -base64 32');
  process.exit(1);
}

// PostgreSQL configuration
const pgConfig = {
  host: process.env.POSTGRES_HOST || 'dashboard-postgres',
  port: parseInt(process.env.POSTGRES_PORT || '5432'),
  database: process.env.POSTGRES_DB || 'dashboard',
  user: process.env.POSTGRES_USER || 'dashboard_app',
  password: process.env.POSTGRES_PASSWORD,
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
  connectionTimeoutMillis: 10000, // Return an error after 10 seconds if connection could not be established
};

// Validate PostgreSQL password
if (!pgConfig.password) {
  console.error('╔════════════════════════════════════════════════════════════╗');
  console.error('║ CRITICAL ERROR: POSTGRES_PASSWORD not configured          ║');
  console.error('║                                                            ║');
  console.error('║ Set a secure random value in your .env file:              ║');
  console.error('║   POSTGRES_PASSWORD=<your-random-password>                ║');
  console.error('║                                                            ║');
  console.error('║ Generate one with:                                        ║');
  console.error('║   openssl rand -base64 32                                 ║');
  console.error('╚════════════════════════════════════════════════════════════╝');
  process.exit(1);
}

// Redis configuration
const redisConfig = {
  socket: {
    host: process.env.REDIS_HOST || 'dashboard-redis',
    port: parseInt(process.env.REDIS_PORT || '6379'),
  },
  password: process.env.REDIS_PASSWORD,
};

// Validate Redis password
if (!redisConfig.password) {
  console.error('╔════════════════════════════════════════════════════════════╗');
  console.error('║ CRITICAL ERROR: REDIS_PASSWORD not configured             ║');
  console.error('║                                                            ║');
  console.error('║ Set a secure random value in your .env file:              ║');
  console.error('║   REDIS_PASSWORD=<your-random-password>                   ║');
  console.error('║                                                            ║');
  console.error('║ Generate one with:                                        ║');
  console.error('║   openssl rand -base64 32                                 ║');
  console.error('╚════════════════════════════════════════════════════════════╝');
  process.exit(1);
}

// Create Redis client
const redisClient = createClient(redisConfig);

redisClient.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
  console.log('✓ Connected to Redis');
});

// Connect to Redis
(async () => {
  try {
    await redisClient.connect();
  } catch (err) {
    console.error('╔════════════════════════════════════════════════════════════╗');
    console.error('║ CRITICAL ERROR: Redis connection failed                   ║');
    console.error('║                                                            ║');
    console.error('║ Error:', err.message);
    console.error('║                                                            ║');
    console.error('║ Check that:                                               ║');
    console.error('║ 1. Redis container is running                             ║');
    console.error('║ 2. REDIS_HOST, REDIS_PORT are correct                     ║');
    console.error('║ 3. REDIS_PASSWORD matches .env file                       ║');
    console.error('╚════════════════════════════════════════════════════════════╝');
    process.exit(1);
  }
})();

// Redis cache helper functions
const cache = {
  /**
   * Get cached value
   * @param {string} key - Cache key
   * @returns {Promise<any>} - Cached value or null
   */
  async get(key) {
    try {
      const value = await redisClient.get(key);
      return value ? JSON.parse(value) : null;
    } catch (err) {
      console.error(`Cache get error for key ${key}:`, err);
      return null; // Fail gracefully
    }
  },

  /**
   * Set cached value with TTL
   * @param {string} key - Cache key
   * @param {any} value - Value to cache
   * @param {number} ttl - Time to live in seconds (default: 60)
   */
  async set(key, value, ttl = 60) {
    try {
      await redisClient.setEx(key, ttl, JSON.stringify(value));
    } catch (err) {
      console.error(`Cache set error for key ${key}:`, err);
      // Fail gracefully - don't break the application if cache fails
    }
  },

  /**
   * Delete cached value
   * @param {string} key - Cache key
   */
  async del(key) {
    try {
      await redisClient.del(key);
    } catch (err) {
      console.error(`Cache delete error for key ${key}:`, err);
    }
  },

  /**
   * Delete multiple keys matching a pattern
   * @param {string} pattern - Key pattern (e.g., 'services:*')
   */
  async delPattern(pattern) {
    try {
      const keys = await redisClient.keys(pattern);
      if (keys.length > 0) {
        await redisClient.del(keys);
      }
    } catch (err) {
      console.error(`Cache delete pattern error for ${pattern}:`, err);
    }
  },

  /**
   * Check if key exists
   * @param {string} key - Cache key
   * @returns {Promise<boolean>}
   */
  async exists(key) {
    try {
      const result = await redisClient.exists(key);
      return result === 1;
    } catch (err) {
      console.error(`Cache exists error for key ${key}:`, err);
      return false;
    }
  }
};

const NGINX_CONTAINER = 'arr-proxy';
const NGINX_CONFIG_FILE = '/etc/nginx/conf.d/default.conf';
const NGINX_CONFIG_HOST_PATH = '/opt/nginx/conf.d/default.conf';

// SECURITY: Input length limits to prevent DoS
const INPUT_LIMITS = {
  username: 50,
  password: 128,
  displayName: 100,
  serviceName: 100,
  servicePath: 200,
  serviceUrl: 500,
  categoryName: 100,
  categoryId: 50,
  nginxConfig: 50000 // 50KB limit for nginx config
};

// SECURITY: Sanitize sensitive data from logs and error messages
function sanitizeForLogging(message) {
  if (typeof message !== 'string') {
    message = JSON.stringify(message);
  }

  // Redact API keys in URLs
  message = message.replace(/apikey=[^&\s]+/gi, 'apikey=[REDACTED]');
  message = message.replace(/api_key=[^&\s]+/gi, 'api_key=[REDACTED]');

  // Redact tokens
  message = message.replace(/token["\s:=]+[a-zA-Z0-9._-]+/gi, 'token=[REDACTED]');

  // Redact passwords
  message = message.replace(/"password":\s*"[^"]+"/gi, '"password":"[REDACTED]"');
  message = message.replace(/password=[^&\s]+/gi, 'password=[REDACTED]');

  // Redact authorization headers
  message = message.replace(/authorization:\s*[^\s,}]+/gi, 'authorization: [REDACTED]');
  message = message.replace(/x-api-key:\s*[^\s,}]+/gi, 'x-api-key: [REDACTED]');

  return message;
}

// SECURITY: Safe console.error wrapper
function secureLog(level, ...args) {
  const sanitized = args.map(arg =>
    typeof arg === 'string' ? sanitizeForLogging(arg) : arg
  );
  console[level](...sanitized);
}

// SECURITY: Validate input length to prevent DoS
function validateInputLength(value, fieldName, maxLength) {
  if (!value) return { valid: true };

  if (typeof value !== 'string') {
    return { valid: false, error: `${fieldName} must be a string` };
  }

  if (value.length > maxLength) {
    return { valid: false, error: `${fieldName} exceeds maximum length of ${maxLength} characters` };
  }

  return { valid: true };
}

// SECURITY: Strong password policy validation
function validatePasswordStrength(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required' };
  }

  // Minimum 12 characters
  if (password.length < 12) {
    return { valid: false, error: 'Password must be at least 12 characters long' };
  }

  // Maximum 128 characters (prevent DoS)
  if (password.length > 128) {
    return { valid: false, error: 'Password must be less than 128 characters' };
  }

  // Must contain at least one lowercase letter
  if (!/[a-z]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one lowercase letter' };
  }

  // Must contain at least one uppercase letter
  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one uppercase letter' };
  }

  // Must contain at least one number
  if (!/\d/.test(password)) {
    return { valid: false, error: 'Password must contain at least one number' };
  }

  // Must contain at least one special character
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one special character (!@#$%^&*()_+-=[]{};\':"|,.<>/?)' };
  }

  return { valid: true };
}

/**
 * NGINX PROXY MANAGEMENT - arr-proxy Container
 *
 * This dashboard manages nginx running in the 'arr-proxy' container.
 * Location blocks are added to /etc/nginx/conf.d/default.conf
 *
 * The dashboard container needs access to docker socket to manage nginx:
 * - Volume: -v /var/run/docker.sock:/var/run/docker.sock
 *
 * Location blocks are inserted BEFORE the root "/" location so they
 * take priority over dashboard routes.
 */

// SECURITY: Safe nginx location block removal (prevents ReDoS attacks)
function removeNginxLocationBlock(config, serviceName, servicePath) {
  const lines = config.split('\n');
  const result = [];
  let inTargetBlock = false;
  let bracketCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check if we found the comment marker for this service
    if (line.includes(`# ${serviceName}`)) {
      inTargetBlock = true;
      continue; // Skip the comment line
    }

    if (inTargetBlock) {
      // Count brackets to track block depth
      const openBrackets = (line.match(/{/g) || []).length;
      const closeBrackets = (line.match(/}/g) || []).length;
      bracketCount += openBrackets - closeBrackets;

      // If we've closed all brackets, we're done with this block
      if (bracketCount <= 0) {
        inTargetBlock = false;
        bracketCount = 0;
        continue; // Skip the closing bracket line
      }
      // Skip lines inside the target block
      continue;
    }

    // Keep all other lines
    result.push(line);
  }

  return result.join('\n');
}

// Nginx management functions
async function readNginxConfig() {
  try {
    const result = await execFilePromise('docker', ['exec', NGINX_CONTAINER, 'cat', NGINX_CONFIG_FILE]);
    return { success: true, content: result.stdout };
  } catch (error) {
    secureLog('error', 'Error reading nginx config:', error.message);
    // SECURITY: Don't expose detailed error messages to users
    return { success: false, error: 'Failed to read configuration file' };
  }
}

// SECURITY: SSRF protection - validate URLs before making requests
function isValidServiceUrl(urlString) {
  try {
    const url = new URL(urlString);

    // Only allow HTTP and HTTPS protocols
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { valid: false, error: 'Only HTTP and HTTPS protocols are allowed' };
    }

    // Block private IP ranges and localhost
    const hostname = url.hostname.toLowerCase();

    // Block localhost variations
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' ||
        hostname === '0.0.0.0' || hostname === '::') {
      return { valid: false, error: 'Localhost addresses are not allowed' };
    }

    // Block private IPv4 ranges
    const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = hostname.match(ipv4Regex);
    if (match) {
      const [, a, b, c, d] = match.map(Number);

      // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
      if (a === 10 ||
          (a === 172 && b >= 16 && b <= 31) ||
          (a === 192 && b === 168)) {
        // Allow internal network (arr services are on 10.99.0.0/16)
        if (a === 10 && b === 99) {
          return { valid: true };
        }
        return { valid: false, error: 'Private IP addresses are not allowed' };
      }

      // 127.0.0.0/8 (already caught above but double-check)
      if (a === 127) {
        return { valid: false, error: 'Loopback addresses are not allowed' };
      }

      // 169.254.0.0/16 (link-local)
      if (a === 169 && b === 254) {
        return { valid: false, error: 'Link-local addresses are not allowed' };
      }
    }

    // Block IPv6 private ranges
    if (hostname.includes(':')) {
      // fc00::/7 (unique local)
      if (hostname.startsWith('fc') || hostname.startsWith('fd')) {
        return { valid: false, error: 'IPv6 private addresses are not allowed' };
      }
      // fe80::/10 (link-local)
      if (hostname.startsWith('fe8') || hostname.startsWith('fe9') ||
          hostname.startsWith('fea') || hostname.startsWith('feb')) {
        return { valid: false, error: 'IPv6 link-local addresses are not allowed' };
      }
    }

    return { valid: true };
  } catch (error) {
    return { valid: false, error: 'Invalid URL format' };
  }
}

async function writeNginxConfig(content) {
  try {
    // SECURITY: Validate and sanitize nginx config before writing

    // 1. Sanitize dangerous directives that could lead to code execution
    const dangerous = [
      'lua_code_block',
      'lua_need_request_body',
      'perl_modules',
      'perl_require',
      'perl_set',
      'alias /etc',
      'alias /var',
      'alias /root',
      'alias /proc',
      'alias /sys'
    ];

    for (const pattern of dangerous) {
      if (content.toLowerCase().includes(pattern.toLowerCase())) {
        throw new Error(`Forbidden directive: ${pattern}`);
      }
    }

    // 2. Create backup before writing
    if (fs.existsSync(NGINX_CONFIG_HOST_PATH)) {
      const backup = `${NGINX_CONFIG_HOST_PATH}.backup.${Date.now()}`;
      fs.copyFileSync(NGINX_CONFIG_HOST_PATH, backup);

      // Keep only last 5 backups
      const dir = path.dirname(NGINX_CONFIG_HOST_PATH);
      const backups = fs.readdirSync(dir)
        .filter(f => f.includes('.backup.'))
        .map(f => ({ name: f, path: path.join(dir, f), time: fs.statSync(path.join(dir, f)).mtime }))
        .sort((a, b) => b.time - a.time);

      // Delete old backups (keep newest 5)
      backups.slice(5).forEach(backup => {
        try {
          fs.unlinkSync(backup.path);
        } catch (err) {
          secureLog('warn', 'Failed to delete old backup:', backup.name);
        }
      });
    }

    // 3. Write config with restricted permissions (rw-r--r--)
    fs.writeFileSync(NGINX_CONFIG_HOST_PATH, content, {
      encoding: 'utf8',
      mode: 0o644
    });

    console.log('Nginx config written successfully (validated & sanitized)');
    return { success: true };
  } catch (error) {
    secureLog('error', 'Error writing nginx config:', error.message);
    // SECURITY: Don't expose detailed error messages to users
    return { success: false, error: 'Failed to write configuration file' };
  }
}

async function addNginxLocation(servicePath, proxyTarget, serviceName) {
  if (!proxyTarget || !servicePath.startsWith('/')) {
    return { success: false, error: 'Invalid proxy configuration' };
  }

  if (!proxyTarget.startsWith('http://') && !proxyTarget.startsWith('https://')) {
    return { success: false, error: 'Proxy target must start with http:// or https://' };
  }

  // SECURITY: SSRF protection
  const urlValidation = isValidServiceUrl(proxyTarget);
  if (!urlValidation.valid) {
    return { success: false, error: `SSRF protection: ${urlValidation.error}` };
  }

  // Read current nginx config
  const readResult = await readNginxConfig();
  if (!readResult.success) {
    return readResult;
  }

  let config = readResult.content;

  // SECURITY: Remove location if exists using safe string operations (prevents ReDoS)
  config = removeNginxLocationBlock(config, serviceName, servicePath);

  // Extract target host for Host header and ensure trailing slash for external domains
  let targetHost = '$host';
  let finalProxyTarget = proxyTarget;

  try {
    const url = new URL(proxyTarget);
    targetHost = url.host;

    // If the proxy target is just a domain (no path), add trailing slash
    if (url.pathname === '' || url.pathname === '/') {
      finalProxyTarget = proxyTarget.replace(/\/?$/, '/');
    }
  } catch (e) {
    // If URL parsing fails, use $host
  }

  // Create new location block with redirect handling
  const locationBlock = `
    # ${serviceName}
    location ${servicePath} {
        proxy_pass ${finalProxyTarget};
        proxy_set_header Host ${targetHost};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_ssl_server_name on;
        proxy_redirect off;
        proxy_buffering off;
    }
`;

  // Insert before the root "/" location (dashboard must be last)
  const rootLocationIndex = config.indexOf('location / {');
  if (rootLocationIndex === -1) {
    return { success: false, error: 'Could not find root location in nginx config' };
  }

  config = config.slice(0, rootLocationIndex) + locationBlock + '\n' + config.slice(rootLocationIndex);

  // Write back
  const writeResult = await writeNginxConfig(config);
  if (!writeResult.success) {
    return writeResult;
  }

  console.log(`Added nginx location for ${serviceName} at ${servicePath}`);
  return { success: true };
}

async function removeNginxLocation(servicePath, serviceName) {
  // Read current nginx config
  const readResult = await readNginxConfig();
  if (!readResult.success) {
    return readResult;
  }

  let config = readResult.content;

  // SECURITY: Remove location using safe string operations (prevents ReDoS)
  config = removeNginxLocationBlock(config, serviceName, servicePath);

  // Write back
  const writeResult = await writeNginxConfig(config);
  if (!writeResult.success) {
    return writeResult;
  }

  console.log(`Removed nginx location for ${serviceName} at ${servicePath}`);
  return { success: true };
}

async function reloadNginx() {
  try {
    // Test config first
    const testResult = await execFilePromise('docker', ['exec', NGINX_CONTAINER, 'nginx', '-t']);
    secureLog('log', 'Nginx config test:', sanitizeForLogging(testResult.stdout || testResult.stderr));

    // Reload nginx
    await execFilePromise('docker', ['exec', NGINX_CONTAINER, 'nginx', '-s', 'reload']);
    console.log('Nginx reloaded successfully');
    return { success: true, message: 'Nginx reloaded successfully' };
  } catch (error) {
    secureLog('error', 'Error reloading nginx:', error.message);
    // SECURITY: Don't expose detailed error messages to users
    return { success: false, error: 'Failed to reload nginx server' };
  }
}

// Trust proxy for X-Forwarded-* headers (required for Cloudflare/nginx)
// SECURITY: Only trust arr-proxy network, not arbitrary X-Forwarded-For headers
app.set('trust proxy', ['172.19.0.0/16']);

// SECURITY: Helmet - Comprehensive security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Needed for inline scripts in dashboard
      styleSrc: ["'self'", "'unsafe-inline'"], // Needed for inline styles
      imgSrc: ["'self'", "data:", "https:", "http:"], // Allow external service icons
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// SECURITY: Rate limiting for login endpoint to prevent brute force attacks
// Use Redis-backed store for distributed rate limiting
const loginLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.sendCommand(args),
    prefix: 'rl:login:',
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per 15 minutes per IP
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
});

// SECURITY: General API rate limiting with Redis store
const apiLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.sendCommand(args),
    prefix: 'rl:api:',
  }),
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute per IP
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use('/api/', apiLimiter);

// SECURITY: CSRF Protection for state-changing operations
const csrfSecret = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => csrfSecret,
  cookieName: 'csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    path: '/',
    secure: false, // Will be set to true when behind HTTPS proxy
    httpOnly: true
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getSessionIdentifier: (req) => req.user?.id || 'anonymous'
});

// Provide CSRF token to frontend
app.get('/api/csrf-token', (req, res) => {
  const token = generateCsrfToken(req, res);
  res.json({ token });
});

// Serve static files with no-cache for CSS/JS to ensure updates are seen immediately
app.use(express.static('public', {
  setHeaders: (res, path) => {
    if (path.endsWith('.css') || path.endsWith('.js')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

// Initialize PostgreSQL connection pool
const pool = new Pool(pgConfig);

// Test connection on startup
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('╔════════════════════════════════════════════════════════════╗');
    console.error('║ CRITICAL ERROR: PostgreSQL connection failed              ║');
    console.error('║                                                            ║');
    console.error('║ Error:', err.message);
    console.error('║                                                            ║');
    console.error('║ Check that:                                               ║');
    console.error('║ 1. PostgreSQL container is running                        ║');
    console.error('║ 2. POSTGRES_HOST, POSTGRES_PORT are correct              ║');
    console.error('║ 3. POSTGRES_PASSWORD matches .env file                    ║');
    console.error('╚════════════════════════════════════════════════════════════╝');
    process.exit(1);
  }
  console.log('✓ Connected to PostgreSQL database');
});

// Handle pool errors
pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL error:', err);
  process.exit(-1);
});

// Database schema initialized via docker-entrypoint-initdb.d/01-schema.sql
// Data migrated via database/migrate-sqlite-to-postgres.js

// JWT verification middleware
const verifyToken = async (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    // For API requests, return JSON error
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Access denied' });
    }
    // For page requests, redirect to login with return path
    const returnPath = encodeURIComponent(req.originalUrl || req.path);
    return res.redirect(`/login?return=${returnPath}`);
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);

    // Fetch full user details including role and permissions
    const result = await pool.query(
      'SELECT id, username, display_name, email, role, permissions, password_must_change, is_active FROM users WHERE id = $1',
      [verified.id]
    );

    if (result.rows.length === 0 || !result.rows[0].is_active) {
      res.clearCookie('token');
      if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      const returnPath = encodeURIComponent(req.originalUrl || req.path);
      return res.redirect(`/login?return=${returnPath}`);
    }

    const user = result.rows[0];
    req.user = {
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      passwordMustChange: user.password_must_change
    };

    next();
  } catch (err) {
    res.clearCookie('token');
    // For API requests, return JSON error
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    // For page requests, redirect to login with return path
    const returnPath = encodeURIComponent(req.originalUrl || req.path);
    return res.redirect(`/login?return=${returnPath}`);
  }
};

// Attach permission helpers to all routes (applied after authentication)
// This adds req.can(), req.hasRole(), etc. helpers to authenticated routes
app.use(attachPermissions());

// SECURITY: Content-Type validation middleware
const validateContentType = (req, res, next) => {
  // Only validate POST, PUT, PATCH, DELETE requests with a body
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const contentType = req.get('Content-Type');

    // Allow requests without body (logout, etc.)
    if (!req.body || Object.keys(req.body).length === 0) {
      return next();
    }

    // Require application/json for requests with body
    if (!contentType || !contentType.includes('application/json')) {
      return res.status(415).json({
        error: 'Unsupported Media Type',
        message: 'Content-Type must be application/json'
      });
    }
  }

  next();
};

// Routes
app.post('/api/login', loginLimiter, validateContentType, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // SECURITY: Input length validation
  const usernameValidation = validateInputLength(username, 'Username', INPUT_LIMITS.username);
  if (!usernameValidation.valid) {
    return res.status(400).json({ error: usernameValidation.error });
  }

  const passwordValidation = validateInputLength(password, 'Password', INPUT_LIMITS.password);
  if (!passwordValidation.valid) {
    return res.status(400).json({ error: passwordValidation.error });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    let user = result.rows.length > 0 ? result.rows[0] : null;

    // SECURITY: Check if account is locked
    if (user && user.locked_until) {
      const lockedUntil = new Date(user.locked_until);
      const now = new Date();

      if (now < lockedUntil) {
        const minutesRemaining = Math.ceil((lockedUntil - now) / 60000);
        return res.status(423).json({
          error: `Account is locked due to too many failed login attempts. Please try again in ${minutesRemaining} minute(s).`
        });
      } else {
        // Lock period expired, reset failed attempts
        await pool.query('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);
        user.failed_login_attempts = 0;
        user.locked_until = null;
      }
    }

    // SECURITY: Timing attack mitigation - always perform password comparison
    // even if user doesn't exist, using a dummy hash
    const dummyHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'; // Pre-computed hash
    const hashToCompare = user ? user.password : dummyHash;

    const isValid = await bcrypt.compare(password, hashToCompare);

    // Always check both conditions to prevent timing leaks
    if (!isValid || !user) {
      // SECURITY: Increment failed login attempts
      if (user) {
        const failedAttempts = (user.failed_login_attempts || 0) + 1;
        const maxAttempts = 10;

        if (failedAttempts >= maxAttempts) {
          // Lock account for 30 minutes
          const lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
          try {
            await pool.query('UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
              [failedAttempts, lockUntil.toISOString(), user.id]);
          } catch (err) {
            secureLog('error', 'Failed to lock account:', err);
          }
          return res.status(423).json({
            error: 'Account locked due to too many failed login attempts. Please try again in 30 minutes.'
          });
        } else {
          // Increment failed attempts
          await pool.query('UPDATE users SET failed_login_attempts = $1 WHERE id = $2', [failedAttempts, user.id]);
        }
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // SECURITY: Reset failed login attempts on successful login
    await pool.query('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Set secure flag based on protocol (HTTPS via Cloudflare or HTTP locally)
    const isSecure = req.protocol === 'https' || req.headers['x-forwarded-proto'] === 'https';

    res.cookie('token', token, {
      httpOnly: true,
      secure: isSecure,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
      path: '/'
    });

    // Security: Return password change requirement status
    res.json({
      success: true,
      username: user.username,
      role: user.role,
      passwordMustChange: user.password_must_change === true
    });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/logout', validateContentType, doubleCsrfProtection, (req, res) => {
  res.clearCookie('token', { path: '/' });
  res.json({ success: true });
});

app.post('/api/change-password', verifyToken, validateContentType, doubleCsrfProtection, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }

  // SECURITY: Input length validation
  const currentPwdValidation = validateInputLength(currentPassword, 'Current password', INPUT_LIMITS.password);
  if (!currentPwdValidation.valid) {
    return res.status(400).json({ error: currentPwdValidation.error });
  }

  const newPwdValidation = validateInputLength(newPassword, 'New password', INPUT_LIMITS.password);
  if (!newPwdValidation.valid) {
    return res.status(400).json({ error: newPwdValidation.error });
  }

  // SECURITY: Strong password policy
  const strengthValidation = validatePasswordStrength(newPassword);
  if (!strengthValidation.valid) {
    return res.status(400).json({ error: strengthValidation.error });
  }

  const userId = req.user.id;

  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = result.rows.length > 0 ? result.rows[0] : null;

    // SECURITY: Timing attack mitigation - always perform password comparison
    const dummyHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';
    const hashToCompare = user ? user.password : dummyHash;

    const isValid = await bcrypt.compare(currentPassword, hashToCompare);

    if (!isValid || !user) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hash = await bcrypt.hash(newPassword, 10);

    // Security: Clear password_must_change flag when password is successfully changed
    await pool.query('UPDATE users SET password = $1, password_must_change = false WHERE id = $2', [hash, userId]);

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to update password' });
  }
});

app.post('/api/change-display-name', verifyToken, validateContentType, doubleCsrfProtection, async (req, res) => {
  const { displayName } = req.body;

  if (!displayName || !displayName.trim()) {
    return res.status(400).json({ error: 'Display name is required' });
  }

  const trimmedName = displayName.trim();

  // SECURITY: Input length validation
  const nameValidation = validateInputLength(trimmedName, 'Display name', INPUT_LIMITS.displayName);
  if (!nameValidation.valid) {
    return res.status(400).json({ error: nameValidation.error });
  }

  if (trimmedName.length < 2) {
    return res.status(400).json({ error: 'Display name must be at least 2 characters' });
  }

  const userId = req.user.id;

  try {
    const result = await pool.query('UPDATE users SET display_name = $1 WHERE id = $2', [trimmedName, userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'Display name updated successfully', displayName: trimmedName });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to update display name' });
  }
});

app.get('/api/verify', verifyToken, async (req, res) => {
  // Fetch user details including display_name and password_must_change
  try {
    const result = await pool.query('SELECT username, display_name, password_must_change FROM users WHERE id = $1', [req.user.id]);

    if (result.rows.length === 0) {
      return res.status(500).json({ error: 'Failed to fetch user details' });
    }

    const user = result.rows[0];

    res.json({
      authenticated: true,
      username: user.username,
      displayName: user.display_name || user.username,
      passwordMustChange: user.password_must_change === true
    });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

// User management API endpoints

// Get all users (admin only)
app.get('/api/users', verifyToken, requireAdmin(), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id, username, display_name, email, role,
        last_login_at, last_login_ip,
        failed_login_attempts, locked_until,
        is_active, created_at
      FROM users
      WHERE is_active = true
      ORDER BY created_at DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Create new user (admin only)
app.post('/api/users', verifyToken, requirePermission(PERMISSIONS.USERS_CREATE), validateContentType, doubleCsrfProtection, async (req, res) => {
  try {
    const { username, password, displayName, email, role } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Validate username length
    const usernameValidation = validateInputLength(username, 'Username', INPUT_LIMITS.username);
    if (!usernameValidation.valid) {
      return res.status(400).json({ error: usernameValidation.error });
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ error: passwordValidation.error });
    }

    // Validate role
    const validRoles = ['super_admin', 'admin', 'power_user', 'user', 'read_only'];
    if (role && !validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Check if current user can assign this role
    const { canManageRole } = require('./config/permissions');
    if (role && !canManageRole(req.user.role, role)) {
      return res.status(403).json({
        error: 'You cannot assign this role',
        message: 'You do not have permission to create users with this role'
      });
    }

    // Hash password
    const hash = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(`
      INSERT INTO users (username, password, display_name, email, role, created_by)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, username, display_name, email, role, created_at
    `, [username, hash, displayName || username, email, role || 'user', req.user.id]);

    res.status(201).json({
      message: 'User created successfully',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Create user error:', err);

    // Handle unique constraint violation
    if (err.code === '23505') {
      if (err.constraint === 'users_username_key') {
        return res.status(409).json({ error: 'Username already exists' });
      }
      if (err.constraint === 'users_email_key') {
        return res.status(409).json({ error: 'Email already exists' });
      }
    }

    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Update user (requires permission)
app.put('/api/users/:id', verifyToken, requireCanManageUser(pool), validateContentType, doubleCsrfProtection, async (req, res) => {
  try {
    const userId = req.params.id;
    const { displayName, email, role, isActive } = req.body;

    // Build update query dynamically
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (displayName !== undefined) {
      updates.push(`display_name = $${paramCount++}`);
      values.push(displayName);
    }

    if (email !== undefined) {
      updates.push(`email = $${paramCount++}`);
      values.push(email);
    }

    if (role !== undefined) {
      // Validate role
      const validRoles = ['super_admin', 'admin', 'power_user', 'user', 'read_only'];
      if (!validRoles.includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
      }

      // Check if current user can assign this role
      const { canManageRole } = require('./config/permissions');
      if (!canManageRole(req.user.role, role)) {
        return res.status(403).json({
          error: 'You cannot assign this role',
          message: 'You do not have permission to assign this role'
        });
      }

      updates.push(`role = $${paramCount++}`);
      values.push(role);
    }

    if (isActive !== undefined) {
      updates.push(`is_active = $${paramCount++}`);
      values.push(isActive);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    // Add user ID to values
    values.push(userId);

    const result = await pool.query(`
      UPDATE users
      SET ${updates.join(', ')}, updated_at = NOW()
      WHERE id = $${paramCount}
      RETURNING id, username, display_name, email, role, is_active, updated_at
    `, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'User updated successfully',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Update user error:', err);

    // Handle unique constraint violation
    if (err.code === '23505') {
      if (err.constraint === 'users_email_key') {
        return res.status(409).json({ error: 'Email already exists' });
      }
    }

    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Deactivate user (super admin only)
app.delete('/api/users/:id', verifyToken, requireSuperAdmin(), doubleCsrfProtection, async (req, res) => {
  try {
    const userId = req.params.id;

    // Prevent self-deletion
    if (parseInt(userId) === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    // Soft delete (deactivate)
    const result = await pool.query(`
      UPDATE users
      SET is_active = false, updated_at = NOW()
      WHERE id = $1
      RETURNING id, username
    `, [userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'User deactivated successfully',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Reset user password (admin only)
app.put('/api/users/:id/password', verifyToken, requireCanManageUser(pool), validateContentType, doubleCsrfProtection, async (req, res) => {
  try {
    const userId = req.params.id;
    const { newPassword, requireChange } = req.body;

    if (!newPassword) {
      return res.status(400).json({ error: 'New password required' });
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({ error: passwordValidation.error });
    }

    // Hash password
    const hash = await bcrypt.hash(newPassword, 10);

    // Update password
    const result = await pool.query(`
      UPDATE users
      SET password = $1,
          password_must_change = $2,
          password_changed_at = NOW(),
          updated_at = NOW()
      WHERE id = $3
      RETURNING id, username
    `, [hash, requireChange || false, userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'Password reset successfully',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.get('/api/server-info', verifyToken, (req, res) => {
  const os = require('os');
  const uptime = os.uptime();

  // Format uptime as days, hours, minutes
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);

  let uptimeStr = '';
  if (days > 0) uptimeStr += `${days}d `;
  if (hours > 0) uptimeStr += `${hours}h `;
  uptimeStr += `${minutes}m`;

  // Calculate CPU usage
  const cpus = os.cpus();
  const cpuUsage = cpus.reduce((acc, cpu) => {
    const total = Object.values(cpu.times).reduce((a, b) => a + b, 0);
    const idle = cpu.times.idle;
    return acc + ((total - idle) / total) * 100;
  }, 0) / cpus.length;

  // Calculate memory usage
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsagePercent = (usedMem / totalMem) * 100;

  res.json({
    hostname: os.hostname(),
    uptime: uptimeStr.trim(),
    cpu: `${cpuUsage.toFixed(1)}%`,
    memory: `${memUsagePercent.toFixed(1)}%`,
    memoryUsed: `${(usedMem / 1024 / 1024 / 1024).toFixed(1)}GB`,
    memoryTotal: `${(totalMem / 1024 / 1024 / 1024).toFixed(1)}GB`
  });
});

// Category management API endpoints

// GET all categories
app.get('/api/categories', verifyToken, async (req, res) => {
  try {
    // Check cache first
    const cacheKey = 'categories:all';
    const cached = await cache.get(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    // Cache miss - fetch from database
    const result = await pool.query('SELECT * FROM categories ORDER BY display_order');

    // Store in cache for 5 minutes
    await cache.set(cacheKey, result.rows, 300);

    res.json(result.rows);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

// GET categories with services (for dashboard display)
app.get('/api/dashboard/categories', verifyToken, async (req, res) => {
  try {
    // Check cache first
    const cacheKey = 'dashboard:categories';
    const cached = await cache.get(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    // Cache miss - fetch from database (parallel queries)
    const [categoriesResult, servicesResult] = await Promise.all([
      pool.query('SELECT * FROM categories ORDER BY display_order'),
      pool.query('SELECT * FROM services WHERE enabled = true ORDER BY category, display_order')
    ]);

    const categories = categoriesResult.rows;
    const services = servicesResult.rows;

    // Group services by category and add to categories
    const result = categories.map(cat => ({
      ...cat,
      services: services
        .filter(s => s.category === cat.id)
        .map(service => ({
          id: service.id,
          name: service.name,
          path: service.path,
          icon: service.icon_url,
          category: service.category,
          apiUrl: service.api_url,
          apiKeyEnv: service.api_key_env,
          displayOrder: service.display_order
        }))
    }));

    // Store in cache for 2 minutes (shorter TTL for frequently changing data)
    await cache.set(cacheKey, result, 120);

    res.json(result);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

// POST create new category
app.post('/api/categories', verifyToken, requirePermission(PERMISSIONS.CATEGORIES_CREATE), validateContentType, doubleCsrfProtection, async (req, res) => {
  const { id, name, display_order, color, icon } = req.body;

  if (!id || !name) {
    return res.status(400).json({ error: 'Category ID and name are required' });
  }

  try {
    // Check if category ID already exists
    const checkResult = await pool.query('SELECT id FROM categories WHERE id = $1', [id]);
    if (checkResult.rows.length > 0) {
      return res.status(400).json({ error: 'Category ID already exists' });
    }

    const result = await pool.query(
      'INSERT INTO categories (id, name, display_order, color, icon) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [id, name, display_order || 0, color || '#58a6ff', icon || 'folder']
    );

    // Invalidate caches
    await cache.delPattern('categories:*');
    await cache.delPattern('dashboard:*');

    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    console.error('Error creating category:', err);
    return res.status(500).json({ error: 'Failed to create category' });
  }
});

// PUT update category
app.put('/api/categories/:id', verifyToken, requirePermission(PERMISSIONS.CATEGORIES_EDIT), validateContentType, doubleCsrfProtection, async (req, res) => {
  const { id } = req.params;
  const { name, display_order, color, icon } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Category name is required' });
  }

  try {
    const result = await pool.query(
      'UPDATE categories SET name = $1, display_order = $2, color = $3, icon = $4 WHERE id = $5',
      [name, display_order || 0, color || '#58a6ff', icon || 'folder', id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }

    // Invalidate caches
    await cache.delPattern('categories:*');
    await cache.delPattern('dashboard:*');

    res.json({ success: true });
  } catch (err) {
    console.error('Error updating category:', err);
    return res.status(500).json({ error: 'Failed to update category' });
  }
});

// DELETE category (with safety check)
app.delete('/api/categories/:id', verifyToken, requirePermission(PERMISSIONS.CATEGORIES_DELETE), doubleCsrfProtection, async (req, res) => {
  const { id } = req.params;

  try {
    // Check if any services are using this category
    const countResult = await pool.query('SELECT COUNT(*) as count FROM services WHERE category = $1 AND enabled = true', [id]);
    const count = parseInt(countResult.rows[0].count);

    if (count > 0) {
      return res.status(400).json({
        error: 'Cannot delete category',
        message: `This category has ${count} service(s) assigned to it. Please reassign or delete those services first.`,
        serviceCount: count
      });
    }

    // Safe to delete
    const result = await pool.query('DELETE FROM categories WHERE id = $1', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }

    // Invalidate caches
    await cache.delPattern('categories:*');
    await cache.delPattern('dashboard:*');

    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting category:', err);
    return res.status(500).json({ error: 'Failed to delete category' });
  }
});

// Service management API endpoints

// GET all services from database
app.get('/api/services', verifyToken, async (req, res) => {
  try {
    // Check cache first
    const cacheKey = 'services:all';
    const cached = await cache.get(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    // Cache miss - fetch from database
    const result = await pool.query('SELECT * FROM services WHERE enabled = true ORDER BY category, display_order');

    // Transform rows into frontend format
    const services = {
      contentManagement: [],
      downloadClients: [],
      managementAnalytics: []
    };

    result.rows.forEach(service => {
      const serviceObj = {
        id: service.id,
        name: service.name,
        path: service.path,
        icon: service.icon_url,
        category: service.category,
        serviceType: service.service_type,
        proxyTarget: service.proxy_target,
        apiUrl: service.api_url,
        apiKeyEnv: service.api_key_env
      };

      if (services[service.category]) {
        services[service.category].push(serviceObj);
      }
    });

    // Store in cache for 5 minutes
    await cache.set(cacheKey, services, 300);

    res.json(services);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

// POST create new service
app.post('/api/services', verifyToken, requirePermission(PERMISSIONS.SERVICES_CREATE), validateContentType, doubleCsrfProtection, async (req, res) => {
  const { name, path, icon_url, category, service_type, proxy_target, api_url, api_key_env, display_order } = req.body;

  if (!name || !path || !icon_url || !category || !service_type) {
    return res.status(400).json({ error: 'Missing required fields: name, path, icon_url, category, service_type' });
  }

  // SECURITY: Input length validation
  const nameValidation = validateInputLength(name, 'Service name', INPUT_LIMITS.serviceName);
  if (!nameValidation.valid) {
    return res.status(400).json({ error: nameValidation.error });
  }

  const pathValidation = validateInputLength(path, 'Service path', INPUT_LIMITS.servicePath);
  if (!pathValidation.valid) {
    return res.status(400).json({ error: pathValidation.error });
  }

  const iconValidation = validateInputLength(icon_url, 'Icon URL', INPUT_LIMITS.serviceUrl);
  if (!iconValidation.valid) {
    return res.status(400).json({ error: iconValidation.error });
  }

  if (service_type === 'proxied' && !proxy_target) {
    return res.status(400).json({ error: 'Proxied services require proxy_target' });
  }

  // SECURITY: SSRF protection for proxy_target
  if (proxy_target) {
    const urlValidation = isValidServiceUrl(proxy_target);
    if (!urlValidation.valid) {
      return res.status(400).json({ error: `Invalid proxy_target: ${urlValidation.error}` });
    }
  }

  // SECURITY: SSRF protection for api_url
  if (api_url) {
    const urlValidation = isValidServiceUrl(api_url);
    if (!urlValidation.valid) {
      return res.status(400).json({ error: `Invalid api_url: ${urlValidation.error}` });
    }
  }

  const validCategories = ['contentManagement', 'downloadClients', 'managementAnalytics'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Invalid category' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO services (name, path, icon_url, category, service_type, proxy_target, api_url, api_key_env, display_order) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id',
      [name, path, icon_url, category, service_type, proxy_target || null, api_url || null, api_key_env || null, display_order || 0]
    );

    const serviceId = result.rows[0].id;

    // Create nginx config for proxied services
    let nginxStatus = { configured: false, error: null, warning: null };
    if (service_type === 'proxied') {
      const nginxResult = await addNginxLocation(path, proxy_target, name);
      if (!nginxResult.success) {
        console.warn('Failed to add nginx location:', nginxResult.error);
        nginxStatus.error = nginxResult.error;
        nginxStatus.warning = 'Nginx config update failed. Service saved but proxy may not work. Check that dashboard container has access to docker socket.';
      } else {
        // Reload nginx
        const reloadResult = await reloadNginx();
        if (!reloadResult.success) {
          nginxStatus.warning = 'Nginx location added but reload failed. You may need to reload nginx manually.';
          nginxStatus.error = reloadResult.error;
        } else {
          nginxStatus.configured = true;
        }
      }
    }

    // Invalidate caches
    await cache.delPattern('services:*');
    await cache.delPattern('dashboard:*');

    res.json({
      success: true,
      id: serviceId,
      message: 'Service created successfully',
      nginx: nginxStatus
    });
  } catch (err) {
    if (err.code === '23505') { // PostgreSQL unique violation
      return res.status(409).json({ error: 'Service with this path already exists' });
    }
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

// PUT update existing service
app.put('/api/services/:id', verifyToken, requirePermission(PERMISSIONS.SERVICES_EDIT), validateContentType, doubleCsrfProtection, async (req, res) => {
  const { id } = req.params;
  const { name, path, icon_url, category, service_type, proxy_target, api_url, api_key_env, display_order, enabled } = req.body;

  if (!name || !path || !icon_url || !category || !service_type) {
    return res.status(400).json({ error: 'Missing required fields: name, path, icon_url, category, service_type' });
  }

  // SECURITY: Input length validation
  const nameValidation = validateInputLength(name, 'Service name', INPUT_LIMITS.serviceName);
  if (!nameValidation.valid) {
    return res.status(400).json({ error: nameValidation.error });
  }

  const pathValidation = validateInputLength(path, 'Service path', INPUT_LIMITS.servicePath);
  if (!pathValidation.valid) {
    return res.status(400).json({ error: pathValidation.error });
  }

  const iconValidation = validateInputLength(icon_url, 'Icon URL', INPUT_LIMITS.serviceUrl);
  if (!iconValidation.valid) {
    return res.status(400).json({ error: iconValidation.error });
  }

  if (service_type === 'proxied' && !proxy_target) {
    return res.status(400).json({ error: 'Proxied services require proxy_target' });
  }

  // SECURITY: SSRF protection for proxy_target
  if (proxy_target) {
    const urlValidation = isValidServiceUrl(proxy_target);
    if (!urlValidation.valid) {
      return res.status(400).json({ error: `Invalid proxy_target: ${urlValidation.error}` });
    }
  }

  // SECURITY: SSRF protection for api_url
  if (api_url) {
    const urlValidation = isValidServiceUrl(api_url);
    if (!urlValidation.valid) {
      return res.status(400).json({ error: `Invalid api_url: ${urlValidation.error}` });
    }
  }

  const validCategories = ['contentManagement', 'downloadClients', 'managementAnalytics'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Invalid category' });
  }

  try {
    // First, get the old service info to handle nginx config changes
    const oldServiceResult = await pool.query('SELECT name, path, service_type FROM services WHERE id = $1', [id]);

    if (oldServiceResult.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }

    const oldService = oldServiceResult.rows[0];

    // Delete old nginx location if it was proxied
    if (oldService.service_type === 'proxied') {
      await removeNginxLocation(oldService.path, oldService.name);
    }

    // Update the service
    const result = await pool.query(
      'UPDATE services SET name = $1, path = $2, icon_url = $3, category = $4, service_type = $5, proxy_target = $6, api_url = $7, api_key_env = $8, display_order = $9, enabled = $10 WHERE id = $11',
      [name, path, icon_url, category, service_type, proxy_target || null, api_url || null, api_key_env || null, display_order || 0, enabled !== undefined ? enabled : true, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }

    // Add nginx location for proxied services
    if (service_type === 'proxied') {
      const nginxResult = await addNginxLocation(path, proxy_target, name);
      if (!nginxResult.success) {
        console.warn('Failed to add nginx location:', nginxResult.error);
      } else {
        await reloadNginx();
      }
    } else {
      // Reload nginx to apply deletion
      await reloadNginx();
    }

    // Invalidate caches
    await cache.delPattern('services:*');
    await cache.delPattern('dashboard:*');

    res.json({
      success: true,
      message: 'Service updated successfully',
      nginxConfigured: service_type === 'proxied'
    });
  } catch (err) {
    if (err.code === '23505') { // PostgreSQL unique violation
      return res.status(409).json({ error: 'Service with this path already exists' });
    }
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

// DELETE service (soft delete by setting enabled = false)
app.delete('/api/services/:id', verifyToken, requirePermission(PERMISSIONS.SERVICES_DELETE), doubleCsrfProtection, async (req, res) => {
  const { id } = req.params;

  try {
    // First get the service info to remove nginx config
    const serviceResult = await pool.query('SELECT name, path, service_type FROM services WHERE id = $1', [id]);

    if (serviceResult.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }

    const service = serviceResult.rows[0];

    const result = await pool.query('UPDATE services SET enabled = false WHERE id = $1', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }

    // Delete nginx config if it was proxied
    if (service.service_type === 'proxied') {
      const nginxResult = await removeNginxLocation(service.path, service.name);
      if (nginxResult.success) {
        await reloadNginx();
      }
    }

    // Invalidate caches
    await cache.delPattern('services:*');
    await cache.delPattern('dashboard:*');

    res.json({
      success: true,
      message: 'Service deleted successfully'
    });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

// GET nginx location blocks
app.get('/api/nginx/locations', verifyToken, async (req, res) => {
  try {
    const result = await readNginxConfig();
    if (!result.success) {
      return res.status(500).json({ error: 'Failed to read nginx config' });
    }

    const config = result.content;
    const locations = [];

    // Parse all location blocks (excluding root "/")
    const locationRegex = /#\s*(.+?)\s*\n\s*location\s+(.+?)\s+\{[\s\S]*?proxy_pass\s+(.+?);/g;
    let match;

    while ((match = locationRegex.exec(config)) !== null) {
      const name = match[1].trim();
      const path = match[2].trim();
      const target = match[3].trim();

      // Skip the root location
      if (path !== '/') {
        locations.push({ name, path, target });
      }
    }

    res.json({ success: true, locations });
  } catch (error) {
    console.error('Error parsing nginx locations:', error);
    res.status(500).json({ error: 'Failed to parse nginx locations' });
  }
});

// DELETE nginx location block
app.delete('/api/nginx/locations', verifyToken, validateContentType, doubleCsrfProtection, async (req, res) => {
  try {
    const { path, name } = req.body;

    if (!path || !name) {
      return res.status(400).json({ error: 'Path and name are required' });
    }

    const result = await removeNginxLocation(path, name);
    if (!result.success) {
      return res.status(500).json({ error: 'Failed to remove nginx location' });
    }

    const reloadResult = await reloadNginx();
    if (!reloadResult.success) {
      // SECURITY: Don't expose detailed error messages
      return res.status(500).json({ error: 'Failed to reload nginx server' });
    }

    res.json({ success: true, message: 'Location removed successfully' });
  } catch (error) {
    console.error('Error removing nginx location:', error);
    res.status(500).json({ error: 'Failed to remove nginx location' });
  }
});

// GET nginx configuration
app.get('/api/nginx/config', verifyToken, async (req, res) => {
  try {
    const result = await readNginxConfig();
    if (result.success) {
      res.json({ success: true, config: result.content });
    } else {
      // SECURITY: Don't expose detailed error messages
      res.status(500).json({ error: 'Failed to read configuration file' });
    }
  } catch (error) {
    console.error('Error reading nginx config:', error);
    res.status(500).json({ error: 'Failed to read nginx config' });
  }
});

// PUT nginx configuration
app.put('/api/nginx/config', verifyToken, validateContentType, doubleCsrfProtection, async (req, res) => {
  try {
    const { config } = req.body;

    if (!config) {
      return res.status(400).json({ error: 'Config content is required' });
    }

    // SECURITY: Input length validation to prevent DoS
    const configValidation = validateInputLength(config, 'Nginx config', INPUT_LIMITS.nginxConfig);
    if (!configValidation.valid) {
      return res.status(400).json({ error: configValidation.error });
    }

    // Write the new config
    const writeResult = await writeNginxConfig(config);
    if (!writeResult.success) {
      // SECURITY: Don't expose detailed error messages
      return res.status(500).json({ error: 'Failed to write configuration file' });
    }

    // Test and reload nginx
    const reloadResult = await reloadNginx();
    if (!reloadResult.success) {
      // SECURITY: Don't expose detailed error messages
      return res.status(500).json({
        error: 'Configuration validation failed',
        message: 'The configuration file contains syntax errors. Please review and try again.'
      });
    }

    res.json({
      success: true,
      message: 'Nginx config updated and reloaded successfully'
    });
  } catch (error) {
    console.error('Error updating nginx config:', error);
    res.status(500).json({ error: 'Failed to update nginx config' });
  }
});

app.get('/api/status', verifyToken, async (req, res) => {
  const services = [
    {
      name: 'Sonarr',
      path: '/sonarr',
      url: 'http://10.99.0.10:8989/api/v3/system/status',
      apiKey: process.env.SONARR_API_KEY
    },
    {
      name: 'Sonarr Anime',
      path: '/anime',
      url: 'http://10.99.0.10:8990/api/v3/system/status',
      apiKey: process.env.SONARR_ANIME_API_KEY
    },
    {
      name: 'Radarr',
      path: '/radarr',
      url: 'http://10.99.0.10:7878/api/v3/system/status',
      apiKey: process.env.RADARR_API_KEY
    },
    {
      name: 'Prowlarr',
      path: '/prowlarr',
      url: 'http://10.99.0.10:9696/api/v1/system/status',
      apiKey: process.env.PROWLARR_API_KEY
    },
    {
      name: 'Lidarr',
      path: '/lidarr',
      url: 'http://10.99.0.10:8686/api/v1/system/status',
      apiKey: process.env.LIDARR_API_KEY
    },
    {
      name: 'qBittorrent',
      path: '/qbit/',
      url: 'http://10.99.0.10:8080/api/v2/app/version'
    },
    {
      name: 'SABnzbd',
      path: '/sab',
      url: 'http://10.99.0.10:6789/api?mode=version&output=json'
    },
    {
      name: 'Tautulli',
      path: '/tautulli',
      url: `http://10.99.0.10:8181/tautulli/api/v2?apikey=${process.env.TAUTULLI_API_KEY}&cmd=get_tautulli_info`,
      apiKey: null
    }
  ];

  const statusChecks = services.map(async (service) => {
    // Check cache first (30 second TTL for status checks)
    const cacheKey = `status:${service.name}`;
    const cachedStatus = await cache.get(cacheKey);
    if (cachedStatus) {
      return cachedStatus;
    }

    try {
      const config = {
        timeout: 3000,
        validateStatus: (status) => status < 500
      };

      // Add X-Api-Key header if service requires API key
      if (service.apiKey) {
        config.headers = { 'X-Api-Key': service.apiKey };
      }

      const response = await axios.get(service.url, config);

      // Fetch activity data based on service type
      let activity = null;
      let activityType = 'idle';

      try {
        if (service.name.includes('Sonarr') || service.name === 'Radarr' || service.name === 'Lidarr') {
          // Check queue for *arr services
          const queueUrl = service.url.replace('/system/status', '/queue');
          const queueResponse = await axios.get(queueUrl, config);
          const queueCount = queueResponse.data.totalRecords || queueResponse.data.length || 0;
          if (queueCount > 0) {
            activity = `${queueCount} queued`;
            activityType = 'active';
          }
        } else if (service.name === 'qBittorrent') {
          // Check active torrents
          const torrentUrl = 'http://10.99.0.10:8080/api/v2/torrents/info?filter=downloading';
          const torrentResponse = await axios.get(torrentUrl, { timeout: 3000 });
          const activeCount = torrentResponse.data.length || 0;
          if (activeCount > 0) {
            activity = `${activeCount} active`;
            activityType = 'active';
          }
        } else if (service.name === 'SABnzbd') {
          // Check SABnzbd queue
          const queueUrl = 'http://10.99.0.10:6789/api?mode=queue&output=json';
          const queueResponse = await axios.get(queueUrl, { timeout: 3000 });
          const queueCount = queueResponse.data.queue?.noofslots || 0;
          if (queueCount > 0) {
            activity = `${queueCount} downloading`;
            activityType = 'active';
          }
        } else if (service.name === 'Tautulli') {
          // Check active streams
          const activityUrl = `http://10.99.0.10:8181/tautulli/api/v2?apikey=${process.env.TAUTULLI_API_KEY}&cmd=get_activity`;
          const activityResponse = await axios.get(activityUrl, { timeout: 3000 });
          const streamCount = activityResponse.data.response?.data?.stream_count || 0;
          if (streamCount > 0) {
            activity = `${streamCount} streaming`;
            activityType = 'active';
          }
        } else if (service.name === 'Prowlarr') {
          // Check indexer count
          const indexerUrl = service.url.replace('/system/status', '/indexer');
          const indexerResponse = await axios.get(indexerUrl, config);
          const enabledCount = indexerResponse.data.filter(i => i.enable).length || 0;
          activity = `${enabledCount} indexers`;
          activityType = 'idle';
        }
      } catch (activityErr) {
        // If activity check fails, just don't show activity
        activity = null;
      }

      const statusResult = {
        name: service.name,
        path: service.path,
        status: 'online',
        activity: activity,
        activityType: activityType
      };

      // Cache the result for 30 seconds
      await cache.set(cacheKey, statusResult, 30);

      return statusResult;
    } catch (err) {
      const statusResult = {
        name: service.name,
        path: service.path,
        status: 'offline',
        activity: null,
        activityType: 'idle'
      };

      // Cache offline status for 30 seconds too
      await cache.set(cacheKey, statusResult, 30);

      return statusResult;
    }
  });

  const results = await Promise.all(statusChecks);
  res.json(results);
});

// Serve HTML files
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/', verifyToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', verifyToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/settings', verifyToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'settings.html'));
});

app.get('/nginx', verifyToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'nginx.html'));
});

// Catch-all: redirect to login
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.redirect('/login');
});

// SECURITY: Global error handler - catch any unhandled errors
app.use((err, req, res, next) => {
  // Log error securely (sanitize sensitive data)
  secureLog('error', 'Unhandled error:', err.message);
  console.error('Error stack:', err.stack);

  // Don't expose error details to client
  if (req.path.startsWith('/api/')) {
    return res.status(500).json({
      error: 'Internal server error',
      message: 'An unexpected error occurred. Please try again later.'
    });
  }

  // For HTML pages, redirect to login
  res.redirect('/login?error=server');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  secureLog('error', 'Unhandled Promise Rejection:', reason);
  console.error('Promise:', promise);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  secureLog('error', 'Uncaught Exception:', err.message);
  console.error('Error stack:', err.stack);
  // Exit gracefully after logging
  process.exit(1);
});

app.listen(PORT, () => {
  console.log(`Dashboard server running on port ${PORT}`);
  console.log(`JWT_SECRET: [CONFIGURED] (${JWT_SECRET.length} characters)`);
});

