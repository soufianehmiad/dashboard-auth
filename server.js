const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cookieParser = require('cookie-parser');
const path = require('path');
const axios = require('axios');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-key-in-production';
const DB_PATH = path.join(__dirname, 'data', 'users.db');

// Trust proxy for X-Forwarded-* headers (required for Cloudflare/nginx)
app.set('trust proxy', 1);

// Security: Add HSTS headers for HTTPS enforcement
app.use((req, res, next) => {
  if (req.protocol === 'https' || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  next();
});

// Security: Rate limiting for login endpoint to prevent brute force attacks
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

// Security: General API rate limiting
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

  // Create services table for dynamic service management
  db.run(`CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    icon_url TEXT NOT NULL,
    category TEXT NOT NULL,
    api_url TEXT,
    api_key_env TEXT,
    display_order INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

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

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    bcrypt.compare(password, user.password, (err, isValid) => {
      if (err || !isValid) {
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

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { path: '/' });
  res.json({ success: true });
});

app.post('/api/change-password', verifyToken, (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const userId = req.user.id;

  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    bcrypt.compare(currentPassword, user.password, (err, isValid) => {
      if (err || !isValid) {
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

app.post('/api/change-display-name', verifyToken, (req, res) => {
  const { displayName } = req.body;

  if (!displayName || !displayName.trim()) {
    return res.status(400).json({ error: 'Display name is required' });
  }

  const trimmedName = displayName.trim();

  if (trimmedName.length < 2) {
    return res.status(400).json({ error: 'Display name must be at least 2 characters' });
  }

  if (trimmedName.length > 50) {
    return res.status(400).json({ error: 'Display name must be less than 50 characters' });
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
app.post('/api/services', verifyToken, (req, res) => {
  const { name, path, icon_url, category, api_url, api_key_env, display_order } = req.body;

  if (!name || !path || !icon_url || !category) {
    return res.status(400).json({ error: 'Missing required fields: name, path, icon_url, category' });
  }

  const validCategories = ['contentManagement', 'downloadClients', 'managementAnalytics'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Invalid category' });
  }

  db.run(
    'INSERT INTO services (name, path, icon_url, category, api_url, api_key_env, display_order) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [name, path, icon_url, category, api_url || null, api_key_env || null, display_order || 0],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(409).json({ error: 'Service with this path already exists' });
        }
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({
        success: true,
        id: this.lastID,
        message: 'Service created successfully'
      });
    }
  );
});

// PUT update existing service
app.put('/api/services/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { name, path, icon_url, category, api_url, api_key_env, display_order, enabled } = req.body;

  if (!name || !path || !icon_url || !category) {
    return res.status(400).json({ error: 'Missing required fields: name, path, icon_url, category' });
  }

  const validCategories = ['contentManagement', 'downloadClients', 'managementAnalytics'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: 'Invalid category' });
  }

  db.run(
    'UPDATE services SET name = ?, path = ?, icon_url = ?, category = ?, api_url = ?, api_key_env = ?, display_order = ?, enabled = ? WHERE id = ?',
    [name, path, icon_url, category, api_url || null, api_key_env || null, display_order || 0, enabled !== undefined ? enabled : 1, id],
    function(err) {
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

      res.json({
        success: true,
        message: 'Service updated successfully'
      });
    }
  );
});

// DELETE service (soft delete by setting enabled = 0)
app.delete('/api/services/:id', verifyToken, (req, res) => {
  const { id } = req.params;

  db.run('UPDATE services SET enabled = 0 WHERE id = ?', [id], function(err) {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }

    res.json({
      success: true,
      message: 'Service deleted successfully'
    });
  });
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

// Catch-all: redirect to login
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`Dashboard server running on port ${PORT}`);
  console.log(`JWT_SECRET: ${JWT_SECRET.substring(0, 10)}...`);
});

