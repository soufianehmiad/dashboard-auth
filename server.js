const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
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
const DB_PATH = path.join(__dirname, 'data', 'users.db');
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
    return { success: false, error: error.message };
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
    return { success: false, error: error.message };
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
    return { success: false, error: error.message };
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
// Use composite key (IP + User-Agent) to prevent bypass via IP spoofing
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { error: 'Too many login attempts, please try again in 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many login attempts, please try again in 15 minutes'
    });
  }
});

// SECURITY: General API rate limiting
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: { error: 'Too many requests, please slow down' },
  standardHeaders: true,
  legacyHeaders: false
});

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use('/api/', apiLimiter);

// SECURITY: CSRF Protection for state-changing operations
const csrfSecret = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');
const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => csrfSecret,
  cookieName: 'csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    path: '/',
    secure: false, // Will be set to true when behind HTTPS proxy
    httpOnly: true
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Provide CSRF token to frontend
app.get('/api/csrf-token', (req, res) => {
  const token = generateToken(req, res);
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

// Initialize SQLite database
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error('Database error:', err);
  else console.log('Connected to users.db');
});

// Create users table and default admin user
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT,
    password_must_change INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Add display_name and password_must_change columns if they don't exist (migration for existing databases)
  db.all("PRAGMA table_info(users)", (err, columns) => {
    if (!err) {
      const hasDisplayName = columns.some(col => col.name === 'display_name');
      const hasPasswordMustChange = columns.some(col => col.name === 'password_must_change');

      if (!hasDisplayName) {
        db.run("ALTER TABLE users ADD COLUMN display_name TEXT", (err) => {
          if (err) console.error('Error adding display_name column:', err);
          else console.log('Added display_name column to users table');
        });
      }

      if (!hasPasswordMustChange) {
        db.run("ALTER TABLE users ADD COLUMN password_must_change INTEGER DEFAULT 0", (err) => {
          if (err) console.error('Error adding password_must_change column:', err);
          else console.log('Added password_must_change column to users table');
        });
      }
    }
  });

  // Create categories table
  db.run(`CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    display_order INTEGER DEFAULT 0,
    color TEXT DEFAULT '#58a6ff',
    icon TEXT DEFAULT 'folder',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) console.error('Error creating categories table:', err);

    // Add color column if it doesn't exist (migration)
    db.run(`ALTER TABLE categories ADD COLUMN color TEXT DEFAULT '#58a6ff'`, (err) => {
      // Ignore error if column already exists
      if (err && !err.message.includes('duplicate column')) {
        console.error('Error adding color column:', err);
      }
    });

    // Add icon column if it doesn't exist (migration)
    db.run(`ALTER TABLE categories ADD COLUMN icon TEXT DEFAULT 'folder'`, (err) => {
      // Ignore error if column already exists
      if (err && !err.message.includes('duplicate column')) {
        console.error('Error adding icon column:', err);
      }
    });

    // Initialize default categories if table is empty
    db.get("SELECT COUNT(*) as count FROM categories", (err, row) => {
      if (!err && row.count === 0) {
        const defaultCategories = [
          { id: 'contentManagement', name: 'Content Management', display_order: 1, color: '#1f6feb', icon: 'film' },
          { id: 'downloadClients', name: 'Download Clients', display_order: 2, color: '#238636', icon: 'download' },
          { id: 'managementAnalytics', name: 'Management & Analytics', display_order: 3, color: '#a371f7', icon: 'chart' }
        ];

        defaultCategories.forEach(cat => {
          db.run('INSERT INTO categories (id, name, display_order, color, icon) VALUES (?, ?, ?, ?, ?)',
            [cat.id, cat.name, cat.display_order, cat.color, cat.icon]);
        });
        console.log('Initialized default categories');
      }
    });
  });

  // Create services table for dynamic service management
  db.run(`CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    icon_url TEXT NOT NULL,
    category TEXT NOT NULL,
    service_type TEXT DEFAULT 'external',
    proxy_target TEXT,
    api_url TEXT,
    api_key_env TEXT,
    display_order INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) console.error('Error creating services table:', err);

    // Migration: Add service_type and proxy_target columns if they don't exist
    db.all("PRAGMA table_info(services)", (err, columns) => {
      if (!err) {
        const hasServiceType = columns.some(col => col.name === 'service_type');
        const hasProxyTarget = columns.some(col => col.name === 'proxy_target');

        if (!hasServiceType) {
          db.run("ALTER TABLE services ADD COLUMN service_type TEXT DEFAULT 'external'", (err) => {
            if (err) console.error('Error adding service_type column:', err);
            else console.log('Added service_type column to services table');
          });
        }

        if (!hasProxyTarget) {
          db.run("ALTER TABLE services ADD COLUMN proxy_target TEXT", (err) => {
            if (err) console.error('Error adding proxy_target column:', err);
            else console.log('Added proxy_target column to services table');
          });
        }
      }
    });
  });

  db.get('SELECT username FROM users WHERE username = ?', ['admin'], (err, row) => {
    if (!row) {
      const defaultPassword = 'change_this_password';
      bcrypt.hash(defaultPassword, 10, (err, hash) => {
        if (err) {
          console.error('Error hashing password:', err);
          return;
        }
        // Security: Force password change on first login with default credentials
        db.run('INSERT INTO users (username, password, password_must_change) VALUES (?, ?, ?)', ['admin', hash, 1], (err) => {
          if (err) console.error('Error creating admin:', err);
          else console.log('Default admin user created (admin/change_this_password) - PASSWORD CHANGE REQUIRED');
        });
      });
    }
  });

  // Migrate existing hardcoded services to database (one-time only)
  db.get('SELECT COUNT(*) as count FROM services', (err, row) => {
    if (!err && row.count === 0) {
      console.log('Migrating hardcoded services to database...');
      const defaultServices = [
        { name: 'Sonarr', path: '/sonarr', icon_url: 'https://raw.githubusercontent.com/Sonarr/Sonarr/develop/Logo/128.png', category: 'contentManagement', api_url: 'http://10.99.0.10:8989/api/v3/system/status', api_key_env: 'SONARR_API_KEY', display_order: 1 },
        { name: 'Sonarr Anime', path: '/anime', icon_url: 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/sonarr.png', category: 'contentManagement', api_url: 'http://10.99.0.10:8990/api/v3/system/status', api_key_env: 'SONARR_ANIME_API_KEY', display_order: 2 },
        { name: 'Radarr', path: '/radarr', icon_url: 'https://raw.githubusercontent.com/Radarr/Radarr/develop/Logo/128.png', category: 'contentManagement', api_url: 'http://10.99.0.10:7878/api/v3/system/status', api_key_env: 'RADARR_API_KEY', display_order: 3 },
        { name: 'Lidarr', path: '/lidarr', icon_url: 'https://raw.githubusercontent.com/Lidarr/Lidarr/develop/Logo/128.png', category: 'contentManagement', api_url: 'http://10.99.0.10:8686/api/v1/system/status', api_key_env: 'LIDARR_API_KEY', display_order: 4 },
        { name: 'Prowlarr', path: '/prowlarr', icon_url: 'https://raw.githubusercontent.com/Prowlarr/Prowlarr/develop/Logo/128.png', category: 'contentManagement', api_url: 'http://10.99.0.10:9696/api/v1/system/status', api_key_env: 'PROWLARR_API_KEY', display_order: 5 },
        { name: 'qBittorrent', path: '/qbit/', icon_url: 'https://raw.githubusercontent.com/qbittorrent/qBittorrent/master/src/icons/qbittorrent-tray.svg', category: 'downloadClients', api_url: 'http://10.99.0.10:8080/api/v2/app/version', api_key_env: null, display_order: 1 },
        { name: 'SABnzbd', path: '/sab', icon_url: 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/sabnzbd.png', category: 'downloadClients', api_url: 'http://10.99.0.10:6789/api?mode=version&output=json', api_key_env: null, display_order: 2 },
        { name: 'Tautulli', path: '/tautulli', icon_url: 'https://raw.githubusercontent.com/Tautulli/Tautulli/master/data/interfaces/default/images/logo.png', category: 'managementAnalytics', api_url: `http://10.99.0.10:8181/tautulli/api/v2?apikey=${process.env.TAUTULLI_API_KEY}&cmd=get_tautulli_info`, api_key_env: 'TAUTULLI_API_KEY', display_order: 1 },
        { name: 'Plex', path: 'https://plex.cirrolink.com', icon_url: 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/plex.png', category: 'managementAnalytics', api_url: null, api_key_env: null, display_order: 2 }
      ];

      const stmt = db.prepare('INSERT INTO services (name, path, icon_url, category, api_url, api_key_env, display_order) VALUES (?, ?, ?, ?, ?, ?, ?)');
      defaultServices.forEach(service => {
        stmt.run(service.name, service.path, service.icon_url, service.category, service.api_url, service.api_key_env, service.display_order);
      });
      stmt.finalize(() => {
        console.log('Successfully migrated services to database');
      });
    }
  });
});

// JWT verification middleware
const verifyToken = (req, res, next) => {
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
    req.user = verified;
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

// Routes
app.post('/api/login', loginLimiter, (req, res) => {
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

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    // SECURITY: Timing attack mitigation - always perform password comparison
    // even if user doesn't exist, using a dummy hash
    const dummyHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'; // Pre-computed hash
    const hashToCompare = user ? user.password : dummyHash;

    bcrypt.compare(password, hashToCompare, (err, isValid) => {
      // Always check both conditions to prevent timing leaks
      if (err || !isValid || !user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

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
        passwordMustChange: user.password_must_change === 1
      });
    });
  });
});

app.post('/api/logout', doubleCsrfProtection, (req, res) => {
  res.clearCookie('token', { path: '/' });
  res.json({ success: true });
});

app.post('/api/change-password', verifyToken, doubleCsrfProtection, (req, res) => {
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

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const userId = req.user.id;

  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    // SECURITY: Timing attack mitigation - always perform password comparison
    const dummyHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';
    const hashToCompare = user ? user.password : dummyHash;

    bcrypt.compare(currentPassword, hashToCompare, (err, isValid) => {
      if (err || !isValid || !user) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) {
          return res.status(500).json({ error: 'Error hashing password' });
        }

        // Security: Clear password_must_change flag when password is successfully changed
        db.run('UPDATE users SET password = ?, password_must_change = 0 WHERE id = ?', [hash, userId], (err) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to update password' });
          }

          res.json({ success: true, message: 'Password changed successfully' });
        });
      });
    });
  });
});

app.post('/api/change-display-name', verifyToken, doubleCsrfProtection, (req, res) => {
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

  db.run('UPDATE users SET display_name = ? WHERE id = ?', [trimmedName, userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update display name' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'Display name updated successfully', displayName: trimmedName });
  });
});

app.get('/api/verify', verifyToken, (req, res) => {
  // Fetch user details including display_name and password_must_change
  db.get('SELECT username, display_name, password_must_change FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) {
      return res.status(500).json({ error: 'Failed to fetch user details' });
    }

    res.json({
      authenticated: true,
      username: user.username,
      displayName: user.display_name || user.username,
      passwordMustChange: user.password_must_change === 1
    });
  });
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
app.get('/api/categories', verifyToken, (req, res) => {
  db.all('SELECT * FROM categories ORDER BY display_order', (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// GET categories with services (for dashboard display)
app.get('/api/dashboard/categories', verifyToken, (req, res) => {
  // Get categories first
  db.all('SELECT * FROM categories ORDER BY display_order', (err, categories) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    // Get all services
    db.all('SELECT * FROM services WHERE enabled = 1 ORDER BY category, display_order', (err, services) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

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

      res.json(result);
    });
  });
});

// POST create new category
app.post('/api/categories', verifyToken, doubleCsrfProtection, (req, res) => {
  const { id, name, display_order, color, icon } = req.body;

  if (!id || !name) {
    return res.status(400).json({ error: 'Category ID and name are required' });
  }

  // Check if category ID already exists
  db.get('SELECT id FROM categories WHERE id = ?', [id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (row) {
      return res.status(400).json({ error: 'Category ID already exists' });
    }

    db.run('INSERT INTO categories (id, name, display_order, color, icon) VALUES (?, ?, ?, ?, ?)',
      [id, name, display_order || 0, color || '#58a6ff', icon || 'folder'],
      function(err) {
        if (err) {
          console.error('Error creating category:', err);
          return res.status(500).json({ error: 'Failed to create category' });
        }
        res.json({ success: true, id: this.lastID });
      }
    );
  });
});

// PUT update category
app.put('/api/categories/:id', verifyToken, doubleCsrfProtection, (req, res) => {
  const { id } = req.params;
  const { name, display_order, color, icon } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Category name is required' });
  }

  db.run('UPDATE categories SET name = ?, display_order = ?, color = ?, icon = ? WHERE id = ?',
    [name, display_order || 0, color || '#58a6ff', icon || 'folder', id],
    function(err) {
      if (err) {
        console.error('Error updating category:', err);
        return res.status(500).json({ error: 'Failed to update category' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Category not found' });
      }
      res.json({ success: true });
    }
  );
});

// DELETE category (with safety check)
app.delete('/api/categories/:id', verifyToken, doubleCsrfProtection, (req, res) => {
  const { id } = req.params;

  // Check if any services are using this category
  db.get('SELECT COUNT(*) as count FROM services WHERE category = ? AND enabled = 1', [id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (row.count > 0) {
      return res.status(400).json({
        error: 'Cannot delete category',
        message: `This category has ${row.count} service(s) assigned to it. Please reassign or delete those services first.`,
        serviceCount: row.count
      });
    }

    // Safe to delete
    db.run('DELETE FROM categories WHERE id = ?', [id], function(err) {
      if (err) {
        console.error('Error deleting category:', err);
        return res.status(500).json({ error: 'Failed to delete category' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Category not found' });
      }
      res.json({ success: true });
    });
  });
});

// Service management API endpoints

// GET all services from database
app.get('/api/services', verifyToken, (req, res) => {
  db.all('SELECT * FROM services WHERE enabled = 1 ORDER BY category, display_order', (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    // Transform rows into frontend format
    const services = {
      contentManagement: [],
      downloadClients: [],
      managementAnalytics: []
    };

    rows.forEach(service => {
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

    res.json(services);
  });
});

// POST create new service
app.post('/api/services', verifyToken, doubleCsrfProtection, async (req, res) => {
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

  db.run(
    'INSERT INTO services (name, path, icon_url, category, service_type, proxy_target, api_url, api_key_env, display_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [name, path, icon_url, category, service_type, proxy_target || null, api_url || null, api_key_env || null, display_order || 0],
    async function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(409).json({ error: 'Service with this path already exists' });
        }
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

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

      res.json({
        success: true,
        id: this.lastID,
        message: 'Service created successfully',
        nginx: nginxStatus
      });
    }
  );
});

// PUT update existing service
app.put('/api/services/:id', verifyToken, doubleCsrfProtection, async (req, res) => {
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

  // First, get the old service info to handle nginx config changes
  db.get('SELECT name, path, service_type FROM services WHERE id = ?', [id], async (err, oldService) => {
    if (err || !oldService) {
      return res.status(404).json({ error: 'Service not found' });
    }

    // Delete old nginx location if it was proxied
    if (oldService.service_type === 'proxied') {
      await removeNginxLocation(oldService.path, oldService.name);
    }

    // Update the service
    db.run(
      'UPDATE services SET name = ?, path = ?, icon_url = ?, category = ?, service_type = ?, proxy_target = ?, api_url = ?, api_key_env = ?, display_order = ?, enabled = ? WHERE id = ?',
      [name, path, icon_url, category, service_type, proxy_target || null, api_url || null, api_key_env || null, display_order || 0, enabled !== undefined ? enabled : 1, id],
      async function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ error: 'Service with this path already exists' });
          }
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }

        if (this.changes === 0) {
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

        res.json({
          success: true,
          message: 'Service updated successfully',
          nginxConfigured: service_type === 'proxied'
        });
      }
    );
  });
});

// DELETE service (soft delete by setting enabled = 0)
app.delete('/api/services/:id', verifyToken, doubleCsrfProtection, async (req, res) => {
  const { id } = req.params;

  // First get the service info to remove nginx config
  db.get('SELECT name, path, service_type FROM services WHERE id = ?', [id], async (err, service) => {
    if (err || !service) {
      return res.status(404).json({ error: 'Service not found' });
    }

    db.run('UPDATE services SET enabled = 0 WHERE id = ?', [id], async function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Service not found' });
      }

      // Delete nginx config if it was proxied
      if (service.service_type === 'proxied') {
        const nginxResult = await removeNginxLocation(service.path, service.name);
        if (nginxResult.success) {
          await reloadNginx();
        }
      }

      res.json({
        success: true,
        message: 'Service deleted successfully'
      });
    });
  });
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
app.delete('/api/nginx/locations', verifyToken, doubleCsrfProtection, async (req, res) => {
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
      return res.status(500).json({ error: 'Nginx reload failed', details: reloadResult.error });
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
      res.status(500).json({ error: 'Failed to read nginx config', details: result.error });
    }
  } catch (error) {
    console.error('Error reading nginx config:', error);
    res.status(500).json({ error: 'Failed to read nginx config' });
  }
});

// PUT nginx configuration
app.put('/api/nginx/config', verifyToken, doubleCsrfProtection, async (req, res) => {
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
      return res.status(500).json({ error: 'Failed to write nginx config', details: writeResult.error });
    }

    // Test and reload nginx
    const reloadResult = await reloadNginx();
    if (!reloadResult.success) {
      return res.status(500).json({
        error: 'Config syntax error',
        details: reloadResult.error,
        message: 'Nginx config was updated but failed validation. Please fix the syntax errors.'
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

      return {
        name: service.name,
        path: service.path,
        status: 'online',
        activity: activity,
        activityType: activityType
      };
    } catch (err) {
      return {
        name: service.name,
        path: service.path,
        status: 'offline',
        activity: null,
        activityType: 'idle'
      };
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

app.listen(PORT, () => {
  console.log(`Dashboard server running on port ${PORT}`);
  console.log(`JWT_SECRET: [CONFIGURED] (${JWT_SECRET.length} characters)`);
});

