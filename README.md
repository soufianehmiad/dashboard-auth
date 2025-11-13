# Dashboard Authentication Application

A secure, modern web dashboard for managing and monitoring services with enterprise-grade authentication and security features.

![Security Rating](https://img.shields.io/badge/Security-⭐⭐⭐⭐⭐-brightgreen)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

## Features

### 🔐 Security
- JWT-based authentication with secure httpOnly cookies
- bcryptjs password hashing (Alpine Linux compatible)
- SQL injection prevention via parameterized queries
- XSS protection through HTML escaping
- Rate limiting on authentication endpoints (5 attempts/15min)
- HSTS headers for HTTPS enforcement
- Forced password change for default credentials
- CSRF protection via sameSite cookies
- Comprehensive input validation

### 📊 Dashboard
- Real-time service status monitoring
- 7 live metrics (CPU, Memory, Disk, Network, Uptime, Docker containers, Services)
- Smart auto-refresh with change detection (10-second polling)
- Service health checks via API endpoints
- Categorized service organization
- Responsive design

### 👤 User Management
- User profile management
- Display name customization
- Secure password change functionality
- Session management
- Protected routes with token verification

### 🎯 Service Management
- Full CRUD operations for services
- Database-driven service configuration
- Service categories (Content Management, Download Clients, Management & Analytics)
- Custom icons and paths
- API integration for status checks
- Display order management

## Quick Start

### Prerequisites
- Node.js >= 18.0.0
- Docker (optional, for containerized deployment)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/dashboard-auth.git
cd dashboard-auth
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Start the application:
```bash
npm start
```

5. Access the dashboard at `http://localhost:3000`

### Default Credentials
- **Username:** `admin`
- **Password:** `change_this_password`

⚠️ **IMPORTANT:** You will be forced to change the default password on first login for security.

## Docker Deployment

```bash
docker build -t dashboard-auth .
docker run -d \
  --name dashboard-auth \
  -p 3000:3000 \
  -e JWT_SECRET=your-secret-key-here \
  -v $(pwd)/data:/app/data \
  dashboard-auth
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Secret key for JWT signing | `your-super-secret-jwt-key-change-this` |
| `PORT` | Server port | `3000` |
| `*_API_KEY` | API keys for service integrations | - |

See `.env.example` for all available variables.

## Security Audit

This application has undergone comprehensive security testing. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the complete audit report.

**Security Rating:** ⭐⭐⭐⭐⭐ (5/5 stars)

- ✅ All critical vulnerabilities fixed
- ✅ All high-priority security enhancements implemented
- ✅ Comprehensive testing completed
- ✅ Production-ready with enterprise-grade security

## Project Structure

```
dashboard-auth/
├── server.js                 # Express backend server
├── package.json             # Dependencies and scripts
├── .env.example             # Environment variables template
├── index.html               # Main dashboard page
├── data/                    # SQLite database storage
│   └── users.db            # User database
├── public/                  # Frontend assets
│   ├── css/
│   │   ├── styles.css      # Main styles
│   │   ├── admin.css       # Admin panel styles
│   │   ├── login.css       # Login page styles
│   │   └── settings.css    # Settings page styles
│   ├── js/
│   │   ├── dashboard.js    # Dashboard logic
│   │   ├── admin.js        # Admin panel logic
│   │   ├── login.js        # Login logic
│   │   └── settings.js     # Settings logic
│   └── pages/
│       ├── admin.html      # Admin panel
│       ├── login.html      # Login page
│       └── settings.html   # User settings
├── CLAUDE.md               # Development documentation
└── SECURITY_AUDIT.md       # Security audit report
```

## API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/logout` - User logout
- `GET /api/verify` - Verify JWT token

### User Management
- `POST /api/change-password` - Change user password
- `POST /api/change-display-name` - Update display name

### Service Management
- `GET /api/services` - List all services
- `POST /api/services` - Create new service
- `PUT /api/services/:id` - Update service
- `DELETE /api/services/:id` - Delete service
- `GET /api/status` - Get service health status

### System
- `GET /api/server-info` - Server metrics and statistics

## Rate Limiting

- **Login endpoint:** 5 attempts per 15 minutes
- **General API:** 100 requests per minute

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

If you discover a security vulnerability, please email security@yourdomain.com instead of using the issue tracker.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Express.js and SQLite
- Security best practices from OWASP
- UI inspired by GitHub's design system

## Support

For support, please open an issue on GitHub or contact the maintainers.

---

**Made with ❤️ by Soufiane**
