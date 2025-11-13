# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a secure dashboard application for *arr media services (Sonarr, Radarr, Lidarr, Prowlarr) and related automation tools. It provides a centralized authentication layer, real-time activity monitoring, service management, and status tracking for self-hosted media management services.

**Tech Stack:** Node.js/Express backend with vanilla JavaScript frontend, SQLite database, JWT authentication, bcryptjs password hashing.

**Design Language:** Flat, GitHub-inspired dark theme with no rounded corners, minimal effects, and clean typography.

## Architecture

### Backend (server.js)

The application is a single Express server that handles:

- **Authentication:** JWT-based auth with bcryptjs password hashing (switched from bcrypt for Alpine Linux compatibility). Tokens stored in httpOnly cookies (24h expiration). Dynamic secure flag based on protocol (HTTP local, HTTPS via Cloudflare).
- **Database:** SQLite database at `data/users.db` with two tables:
  - `users`: User authentication and profiles (username, password, display_name)
  - `services`: Service configuration (name, path, icon_url, category, api_url, api_key_env, display_order)
- **Service Management:** Full CRUD API for managing services (add, edit, delete) with database persistence
- **Service Status & Activity Monitoring:** Polls configured *arr services and download clients to check:
  - Online/offline status via API endpoints
  - Real-time activity (queue counts, active downloads, streaming sessions, indexer counts)
  - Service-specific metrics based on type
- **Server Information:** Provides comprehensive system metrics via `/api/server-info`:
  - Hostname and uptime
  - CPU usage percentage
  - Memory usage (percentage and GB used/total)
- **User Profile Management:** API endpoints for changing display name and password
- **Protected Routes:** All routes except `/api/login` and `/login` require JWT authentication via `verifyToken` middleware
- **Proxy Support:** Trusts X-Forwarded-Proto headers for Cloudflare/nginx deployments

### Frontend

Split into four main pages:

1. **login.html + login.js:** Half-page split layout with custom SVG illustration showing media automation architecture on the left, login form on the right
2. **index.html + dashboard.js:** Main dashboard with:
   - Comprehensive metrics bar (Server, Uptime, CPU, Memory, Services, Activity, Last Update)
   - Service cards organized by category (Content Management, Download Clients, Management & Analytics)
   - Real-time activity indicators (green for active, gray for idle)
   - Normal flexbox footer with centered links (GitHub, API Status)
   - Smart auto-refresh every 10 seconds with change detection
   - Server metrics update every 30 seconds
3. **admin.html + admin.js:** Service management page with:
   - List of all configured services
   - Add/Edit/Delete functionality via modal forms
   - Category badges and service details
   - Full CRUD operations against database
4. **settings.html + settings.js:** User settings page with:
   - Display name change (friendly name shown in UI)
   - Password change (current password verification required)
   - Profile management

### Navigation System

All authenticated pages share consistent header with dropdown menu:
- **User Menu Button:** Shows display name (or username) with dropdown arrow
- **Dropdown Menu:**
  - Settings (profile and password management)
  - Manage Services (admin page)
  - Logout (red on hover)
- Fixed navbar height: 60px across all pages for consistency

### Service Configuration

Services are now **database-driven** with API-based management:

**Database (services table):**
```sql
CREATE TABLE services (
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
)
```

**Migration:**
- On first run, server automatically migrates 9 hardcoded services to database
- Migration only runs once (checks for existing services)

**Frontend Fallback:**
- Dashboard loads services from `/api/services` endpoint
- Falls back to hardcoded SERVICES object if API fails
- Ensures dashboard works even if database unavailable

**API Endpoints:**
- `GET /api/services` - Fetch all enabled services grouped by category
- `POST /api/services` - Create new service
- `PUT /api/services/:id` - Update existing service
- `DELETE /api/services/:id` - Soft delete (sets enabled=0)

### Current Working Icon URLs

All icons verified working as of last update:

```javascript
// Content Management
'Sonarr': 'https://raw.githubusercontent.com/Sonarr/Sonarr/develop/Logo/128.png'
'Sonarr Anime': 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/sonarr.png' // + CSS filter
'Radarr': 'https://raw.githubusercontent.com/Radarr/Radarr/develop/Logo/128.png'
'Lidarr': 'https://raw.githubusercontent.com/Lidarr/Lidarr/develop/Logo/128.png'
'Prowlarr': 'https://raw.githubusercontent.com/Prowlarr/Prowlarr/develop/Logo/128.png'

// Download Clients
'qBittorrent': 'https://raw.githubusercontent.com/qbittorrent/qBittorrent/master/src/icons/qbittorrent-tray.svg'
'SABnzbd': 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/sabnzbd.png'

// Management & Analytics
'Tautulli': 'https://raw.githubusercontent.com/Tautulli/Tautulli/master/data/interfaces/default/images/logo.png'
'Plex': 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/plex.png'
```

### Activity Tracking Features

The dashboard shows real-time activity instead of static version numbers:

- **Sonarr/Radarr/Lidarr:** Queue count (e.g., "3 queued") when downloading/importing
- **qBittorrent:** Active torrent count (e.g., "5 active") when downloading
- **SABnzbd:** Download queue (e.g., "2 downloading") when active
- **Tautulli:** Current stream count (e.g., "2 streaming") when people are watching
- **Prowlarr:** Enabled indexer count (e.g., "15 indexers") always visible
- **Plex:** Always marked as online (external service, no status check)

### Dashboard Metrics

Comprehensive metrics bar displays 7 real-time metrics:

1. **Server:** System hostname
2. **Uptime:** Formatted as "Xd Xh Xm" (days, hours, minutes)
3. **CPU:** Current CPU usage percentage (averaged across all cores)
4. **Memory:** Usage percentage with GB breakdown (e.g., "45.2% (3.6GB/8.0GB)")
5. **Services:** Online/total count (e.g., "8/9 Online")
6. **Activity:** Total active items across all services (downloads, queues, streams)
7. **Last Update:** Timestamp of last refresh in 24h format (HH:MM:SS)

**Smart Auto-Refresh:**
- Checks for service changes every 10 seconds
- Only updates UI when actual changes detected (change detection via JSON comparison)
- Server metrics (CPU, memory, uptime) update every 30 seconds
- Efficient: doesn't trigger unnecessary DOM updates

## Design System

### Color Palette
- Background: `#0d1117` (dark)
- Cards/Panels: `#161b22` (slightly lighter)
- Borders: `#30363d` (subtle)
- Text Primary: `#c9d1d9` (light gray)
- Text Secondary: `#8b949e` (muted gray)
- Text Tertiary: `#6e7681` (labels, metadata)
- Accent Blue: `#58a6ff` (links, focus states)
- Success Green: `#3fb950` (online status, active items)
- Error Red: `#f85149` (offline status, danger actions)
- Warning Blue: `#58a6ff` (loading states)

### Design Principles
- **Flat design:** All `border-radius: 0`, no shadows or gradients
- **Minimal animations:** No transitions except for border-color changes
- **Consistent spacing:** 8px base unit for padding/margins
- **Minimal hover effects:** Only border color change on hover, no movement or transforms
- **Consistent navbar:** Fixed 60px height across all pages
- **Normal footer:** Flexbox footer at bottom (not fixed/sticky), centered content

## Deployment

### Docker Container
- Container name: `dashboard-auth`
- Port: 3000 (internal)
- Network: `arr-proxy_arr-network`
- IP: 172.19.0.3
- Base image: node:20-alpine (requires bcryptjs, not bcrypt)

### Reverse Proxy (nginx)
- Container: `arr-proxy`
- Preserves `X-Forwarded-Proto` from Cloudflare
- Proxies to `http://dashboard-auth:3000`

### Cloudflare Tunnel
- External URL: `arr.cirrolink.com`
- HTTPS termination at Cloudflare

## Environment Variables

Required in `.env` file:

```env
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
SONARR_API_KEY=api-key-here
SONARR_ANIME_API_KEY=api-key-here
RADARR_API_KEY=api-key-here
PROWLARR_API_KEY=api-key-here
LIDARR_API_KEY=api-key-here
TAUTULLI_API_KEY=api-key-here
NODE_ENV=production
```

API keys can be retrieved from each service's settings page.

## Common Commands

### Development

```bash
# Install dependencies
npm install

# Start the server (port 3000)
npm start
# or
node server.js
```

### Docker Operations

```bash
# Restart dashboard container
docker restart dashboard-auth

# View logs
docker logs dashboard-auth --tail 50

# Check status
docker ps | grep dashboard-auth

# Reset admin password (if locked out)
docker exec -it dashboard-auth node -e "const bcrypt = require('bcryptjs'); console.log(bcrypt.hashSync('new_password', 10));"
```

## Key Implementation Details

### Adding New Services

Services can now be added through the Admin UI (`/admin`):

1. Click "Add Service" button
2. Fill in service details:
   - Name (display name)
   - Path (URL path, e.g., `/sonarr`)
   - Icon URL (verified working URL)
   - Category (Content Management, Download Clients, Management & Analytics)
   - API URL (optional, for status checks)
   - API Key Environment Variable (optional, e.g., `SONARR_API_KEY`)
   - Display Order (for custom sorting)
3. Save - service immediately available on dashboard

**Manual addition (if needed):**
- Add to database via SQL
- Add API key to `.env` if required
- Add activity logic in server.js if service supports it

### Authentication Flow

1. User submits credentials to `/api/login`
2. Server validates against users table, generates JWT token
3. Token set as httpOnly cookie with 24h expiration
4. Cookie secure flag set dynamically based on protocol
5. All subsequent requests include cookie automatically
6. `verifyToken` middleware validates token on protected routes
7. Expired/invalid tokens redirect to login page with return path

### Database Schema

**users table:**
```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,  -- bcryptjs hashed
  display_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

**services table:**
```sql
CREATE TABLE services (
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
)
```

### Security Notes

- Cookies configured with `httpOnly: true`, `sameSite: 'lax'`
- Secure flag dynamic: `true` for HTTPS (Cloudflare), `false` for local HTTP
- Password hashing uses bcryptjs (not bcrypt) for Alpine Linux compatibility
- Salt rounds: 10
- JWT tokens expire after 24 hours
- Invalid tokens cleared from cookies automatically
- Parameterized SQL queries prevent SQL injection
- API keys stored in environment variables, never committed
- Password change requires current password verification
- Display name and username are separate (username is login identifier, display name is UI label)

### User Profile Management

**Display Name:**
- Separate from username (username is for login only, display name for UI)
- Can be changed at any time via Settings page
- Defaults to username if not set
- Shown in navbar dropdown menu

**Password Change:**
- Requires current password verification
- Minimum 8 characters
- Must confirm new password
- Immediate logout not required (token remains valid)

### Special Service Handling

**Plex:**
- External service at `https://plex.cirrolink.com`
- No status check (always marked online in frontend)
- Not included in backend status endpoint
- Counted separately in service totals

**Sonarr Anime:**
- Uses verified icon from walkxcode/dashboard-icons: `https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/sonarr.png`
- Visual distinction via CSS filter at `dashboard.css:241-243`: `hue-rotate(280deg) saturate(1.8) brightness(1.1)` creates pink/purple tint
- No border or background - transparent like other icons
- Separate instance on port 8990
- Same activity tracking as regular Sonarr

**SABnzbd:**
- Uses verified icon from walkxcode/dashboard-icons: `https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/sabnzbd.png`
- Previous logo-full.svg was too large/wide, PNG icon displays at correct 40px size

### File Structure

```
/opt/dashboard/
├── server.js                    # Express backend
├── index.html                   # Main dashboard (outside public for auth)
├── package.json                 # Dependencies
├── .env                         # Environment variables (not committed)
├── data/
│   └── users.db                # SQLite database (users + services)
├── public/
│   ├── login.html              # Login page
│   ├── admin.html              # Service management page
│   ├── settings.html           # User settings page
│   ├── css/
│   │   ├── dashboard.css       # Dashboard styles (flat UI)
│   │   ├── admin.css           # Admin page styles
│   │   └── login.css           # Login page styles
│   └── js/
│       ├── dashboard.js        # Dashboard logic + fallback services
│       ├── admin.js            # Service management logic
│       ├── settings.js         # User settings logic
│       └── login.js            # Login form handling
└── CLAUDE.md                   # This file
```

### CSS Architecture

**Flexbox Layout:**
- Body: `min-height: 100vh`, `display: flex`, `flex-direction: column`
- Main: `flex: 1` (takes remaining space)
- Footer: Normal footer with `margin-top: 24px` (not fixed)

**Fixed Navbar:**
- Header: `height: 60px` consistent across all pages
- Container: `height: 100%` for vertical centering
- Dropdown menu positioned absolutely (doesn't affect navbar height)

**Service Cards:**
- Fixed height: `110px`
- Grid: `repeat(auto-fill, minmax(120px, 1fr))`
- Gap: `8px`
- Border changes on hover only (no transforms)

**Metrics Bar:**
- Flexbox with wrap
- Gap: `20px`
- Each metric has `min-width: 100px`
- Responsive wrapping on smaller screens

**Login Page:**
- Split layout: 50/50 left (SVG) / right (form)
- Left side hidden on mobile (<1024px)
- Custom SVG illustration representing media automation stack

## Troubleshooting

### Services Show Offline
1. Check API keys in `.env` file
2. Verify service URLs and ports in database (via Admin page)
3. Check service is running: `docker ps`
4. Test API endpoint directly: `curl -H "X-Api-Key: key" http://ip:port/api/v3/system/status`

### Login Redirect Loop
1. Verify `app.set('trust proxy', 1)` in server.js
2. Check nginx preserves `X-Forwarded-Proto` header
3. Verify cookie secure flag logic
4. Clear browser cookies

### Activity Not Showing
1. Check service-specific API endpoints in server.js
2. Verify activity check logic for service type
3. Check browser console for errors
4. Verify timeout settings (default 3000ms)

### Icons Not Showing or Wrong Size
1. **Always verify icon URLs work before using**: `curl -s -I <icon-url> | head -3`
2. **Prefer walkxcode/dashboard-icons PNG versions** for consistency:
   - Format: `https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/<service>.png`
   - Standard size: 512x512 PNG, scales well to 40px
3. **Avoid inline SVG data URIs** - can have encoding issues
4. **Avoid external logo SVGs** (like sabnzbd.org) - often designed for websites, not square icons
5. **Test icon rendering** after changes before declaring success

### Sonarr Anime Icon
- Do NOT create custom SVG backgrounds or borders
- Use same PNG as regular Sonarr from walkxcode/dashboard-icons
- Apply ONLY CSS filter for color distinction: `hue-rotate(280deg) saturate(1.8) brightness(1.1)`
- Keep transparent background, no border squares

### bcrypt vs bcryptjs
- **Alpine Linux Issue:** Native bcrypt module causes SIGSEGV errors in Alpine-based Docker containers
- **Solution:** Use bcryptjs (pure JavaScript implementation)
- **Migration:** If switching, manually reset all user passwords with new bcryptjs hashes
- **Code:** `const bcrypt = require('bcryptjs');` (line 3 in server.js)

### Navbar Height Changes
- Ensure header has `height: 60px` in CSS
- Ensure header .container has `height: 100%`
- Dropdown menu must use `position: absolute` (not affect flow)

### Footer Floating/Not at Bottom
- Body must have `display: flex`, `flex-direction: column`, `min-height: 100vh`
- Main must have `flex: 1`
- Footer should NOT have `position: fixed`

## Notes for Future Claude Instances

### Design & Layout
- All design elements use flat UI (no border-radius, shadows, or gradients)
- Minimal CSS transitions (border-color only)
- Fixed navbar height: 60px across all pages
- Normal flexbox footer (not sticky/fixed) with centered content
- Login page has custom SVG illustration showing media automation stack
- Dropdown menu for navigation (Settings, Manage Services, Logout)

### Service Configuration
- Services are database-driven with CRUD API
- Frontend has fallback to hardcoded SERVICES object
- Activity tracking is service-specific (check server.js for logic)
- Plex is handled differently (external service, no status check)
- Smart refresh every 10s with change detection
- Server metrics update every 30s

### User Management
- Display name separate from username
- Username is immutable login identifier
- Display name shown in UI, can be changed
- Password changes require current password verification
- bcryptjs used (not bcrypt) for Alpine Linux compatibility

### Icons Best Practices
- Always verify icon URLs before using them (curl test)
- Use walkxcode/dashboard-icons PNG format for consistency
- Icons render at 40px × 40px - avoid full logos designed for websites
- Inline SVG data URIs can fail - prefer hosted PNG files
- For Sonarr Anime: use CSS filter only, no custom backgrounds/borders
- Test rendering in browser before considering icon fixed

### Common Pitfalls
- Don't add borders or backgrounds when user says "remove" - they mean it
- Don't create inline SVGs without thorough testing
- Don't assume icon URLs exist - verify with curl first
- Don't add CSS effects when user wants something removed
- Don't use bcrypt in Alpine Linux - use bcryptjs
- Don't make footer sticky if user wants normal footer
- Always maintain consistent navbar height (60px)
- Change detection prevents unnecessary UI updates - use it

### API Endpoints Reference

**Authentication:**
- `POST /api/login` - User login (returns JWT cookie)
- `POST /api/logout` - Clear auth cookie
- `GET /api/verify` - Verify token, return user info

**User Profile:**
- `POST /api/change-display-name` - Update display name
- `POST /api/change-password` - Change password (requires current password)

**Services:**
- `GET /api/services` - Get all enabled services by category
- `POST /api/services` - Create new service
- `PUT /api/services/:id` - Update service
- `DELETE /api/services/:id` - Soft delete service

**Status & Metrics:**
- `GET /api/status` - Service status and activity
- `GET /api/server-info` - Server metrics (hostname, uptime, CPU, memory)
