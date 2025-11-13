-- PostgreSQL Database Schema for Dashboard Authentication Application
-- Version: 2.0 (Enterprise)
-- Date: 2025-11-13

-- Enable UUID extension for future use
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- USERS TABLE
-- ============================================================================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,  -- bcryptjs hash
    display_name VARCHAR(100),
    email VARCHAR(255) UNIQUE,  -- Future: email notifications

    -- Security fields
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    password_must_change BOOLEAN DEFAULT FALSE,
    password_changed_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    last_login_ip INET,

    -- Role and permissions (Phase 3)
    role VARCHAR(50) DEFAULT 'user',  -- 'super_admin', 'admin', 'power_user', 'user', 'read_only'
    permissions JSONB DEFAULT '[]'::JSONB,  -- Additional granular permissions

    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    is_active BOOLEAN DEFAULT TRUE,

    -- Constraints
    CONSTRAINT valid_role CHECK (role IN ('super_admin', 'admin', 'power_user', 'user', 'read_only'))
);

-- Indexes for users table
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_last_login ON users(last_login_at);
CREATE INDEX idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;

-- ============================================================================
-- CATEGORIES TABLE
-- ============================================================================
CREATE TABLE categories (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    display_order INTEGER DEFAULT 0,
    color VARCHAR(7) DEFAULT '#58a6ff',  -- Hex color
    icon VARCHAR(50) DEFAULT 'folder',
    description TEXT,

    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Indexes for categories table
CREATE INDEX idx_categories_display_order ON categories(display_order);

-- ============================================================================
-- SERVICES TABLE
-- ============================================================================
CREATE TABLE services (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    path VARCHAR(200) NOT NULL UNIQUE,
    icon_url VARCHAR(500) NOT NULL,
    category VARCHAR(50) REFERENCES categories(id) ON DELETE RESTRICT,

    -- Service configuration
    service_type VARCHAR(50) DEFAULT 'external',  -- 'external', 'proxied', 'internal'
    proxy_target VARCHAR(500),
    api_url VARCHAR(500),
    api_key_env VARCHAR(100),  -- Environment variable name
    display_order INTEGER DEFAULT 0,

    -- Additional metadata (extensible)
    config JSONB DEFAULT '{}'::JSONB,  -- Service-specific configuration

    -- Status and health
    enabled BOOLEAN DEFAULT TRUE,
    health_check_url VARCHAR(500),
    health_check_interval INTEGER DEFAULT 30,  -- seconds
    last_health_check TIMESTAMPTZ,
    is_healthy BOOLEAN,

    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,

    -- Constraints
    CONSTRAINT valid_service_type CHECK (service_type IN ('external', 'proxied', 'internal'))
);

-- Indexes for services table
CREATE INDEX idx_services_category ON services(category);
CREATE INDEX idx_services_enabled ON services(enabled);
CREATE INDEX idx_services_display_order ON services(display_order);
CREATE INDEX idx_services_config ON services USING GIN(config);  -- JSON index

-- ============================================================================
-- SESSIONS TABLE (for Redis backup and distributed sessions)
-- ============================================================================
CREATE TABLE sessions (
    sid VARCHAR(255) PRIMARY KEY,
    sess JSONB NOT NULL,
    expire TIMESTAMPTZ NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for sessions table
CREATE INDEX idx_sessions_expire ON sessions(expire);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);

-- Auto-cleanup expired sessions
CREATE INDEX idx_sessions_expire_cleanup ON sessions(expire) WHERE expire < NOW();

-- ============================================================================
-- AUDIT_LOGS TABLE (comprehensive activity tracking)
-- ============================================================================
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),

    -- Who
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(50),  -- Denormalized for deleted users

    -- What
    action VARCHAR(100) NOT NULL,  -- 'user.login', 'service.create', etc.
    resource_type VARCHAR(50),     -- 'user', 'service', 'category', 'session'
    resource_id VARCHAR(100),

    -- How
    method VARCHAR(10),            -- HTTP method: GET, POST, PUT, DELETE
    endpoint VARCHAR(255),         -- API endpoint
    ip_address INET,
    user_agent TEXT,

    -- Details
    changes JSONB,                 -- Before/after diff
    metadata JSONB,                -- Additional context

    -- Result
    status VARCHAR(20),            -- 'success', 'failure', 'denied'
    error_message TEXT,

    -- Performance
    duration_ms INTEGER            -- Request duration
);

-- Indexes for audit_logs table
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_status ON audit_logs(status);
CREATE INDEX idx_audit_logs_changes ON audit_logs USING GIN(changes);  -- JSON index

-- Partition by month for better performance (optional, for high-volume)
-- CREATE TABLE audit_logs_2025_11 PARTITION OF audit_logs
--     FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

-- ============================================================================
-- API_KEYS TABLE (for service-to-service authentication - Phase 3)
-- ============================================================================
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(255) UNIQUE NOT NULL,  -- bcrypt hash of API key
    key_prefix VARCHAR(10) NOT NULL,        -- First 8 chars for identification
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Ownership and permissions
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    permissions JSONB DEFAULT '[]'::JSONB,

    -- Rate limiting
    rate_limit INTEGER DEFAULT 100,  -- Requests per minute

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_ip INET,

    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revoked_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    revoke_reason TEXT
);

-- Indexes for api_keys table
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_api_keys_expires ON api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================================
-- TRIGGERS FOR AUTOMATIC TIMESTAMP UPDATES
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to tables with updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_categories_updated_at BEFORE UPDATE ON categories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_services_updated_at BEFORE UPDATE ON services
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- DEFAULT DATA
-- ============================================================================

-- Default categories (migrated from existing data)
INSERT INTO categories (id, name, display_order, color, icon) VALUES
    ('contentManagement', 'Content Management', 1, '#58a6ff', 'film'),
    ('downloadClients', 'Download Clients', 2, '#3fb950', 'download'),
    ('managementAnalytics', 'Management & Analytics', 3, '#f85149', 'chart')
ON CONFLICT (id) DO NOTHING;

-- Default super admin user (password: Admin@123456)
-- NOTE: This should be changed immediately after first login
INSERT INTO users (username, password, display_name, role, password_must_change) VALUES
    ('admin', '$2a$10$rVqkKxW5z4xKpXQjYvL0eeQF.vYZN3ZJxX3Y9K8fZ8KQZ9yZL0QzG', 'Administrator', 'super_admin', TRUE)
ON CONFLICT (username) DO NOTHING;

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Active users with recent activity
CREATE OR REPLACE VIEW active_users AS
SELECT
    u.id,
    u.username,
    u.display_name,
    u.email,
    u.role,
    u.last_login_at,
    u.last_login_ip,
    COUNT(DISTINCT s.sid) as active_sessions
FROM users u
LEFT JOIN sessions s ON u.id = s.user_id AND s.expire > NOW()
WHERE u.is_active = TRUE
GROUP BY u.id, u.username, u.display_name, u.email, u.role, u.last_login_at, u.last_login_ip;

-- Service health summary
CREATE OR REPLACE VIEW service_health AS
SELECT
    s.id,
    s.name,
    s.category,
    c.name as category_name,
    s.enabled,
    s.is_healthy,
    s.last_health_check,
    CASE
        WHEN s.last_health_check IS NULL THEN 'never_checked'
        WHEN s.last_health_check < NOW() - INTERVAL '5 minutes' THEN 'stale'
        WHEN s.is_healthy = TRUE THEN 'healthy'
        ELSE 'unhealthy'
    END as health_status
FROM services s
LEFT JOIN categories c ON s.category = c.id
WHERE s.enabled = TRUE;

-- Recent audit activity
CREATE OR REPLACE VIEW recent_audit_activity AS
SELECT
    a.id,
    a.timestamp,
    a.username,
    u.display_name,
    a.action,
    a.resource_type,
    a.resource_id,
    a.status,
    a.ip_address
FROM audit_logs a
LEFT JOIN users u ON a.user_id = u.id
WHERE a.timestamp > NOW() - INTERVAL '24 hours'
ORDER BY a.timestamp DESC
LIMIT 100;

-- ============================================================================
-- FUNCTIONS FOR AUDIT LOGGING
-- ============================================================================

CREATE OR REPLACE FUNCTION log_audit_event(
    p_user_id INTEGER,
    p_action VARCHAR(100),
    p_resource_type VARCHAR(50),
    p_resource_id VARCHAR(100),
    p_changes JSONB DEFAULT NULL,
    p_metadata JSONB DEFAULT NULL,
    p_status VARCHAR(20) DEFAULT 'success',
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL
)
RETURNS BIGINT AS $$
DECLARE
    v_audit_id BIGINT;
    v_username VARCHAR(50);
BEGIN
    -- Get username
    SELECT username INTO v_username FROM users WHERE id = p_user_id;

    -- Insert audit log
    INSERT INTO audit_logs (
        user_id, username, action, resource_type, resource_id,
        changes, metadata, status, ip_address, user_agent
    ) VALUES (
        p_user_id, v_username, p_action, p_resource_type, p_resource_id,
        p_changes, p_metadata, p_status, p_ip_address, p_user_agent
    ) RETURNING id INTO v_audit_id;

    RETURN v_audit_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- GRANT PERMISSIONS (adjust for your user)
-- ============================================================================

-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO dashboard_app;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO dashboard_app;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO dashboard_app;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE users IS 'User accounts with authentication and authorization';
COMMENT ON TABLE categories IS 'Service categories for dashboard organization';
COMMENT ON TABLE services IS 'Configured services displayed on dashboard';
COMMENT ON TABLE sessions IS 'User session storage (Redis backup and distributed sessions)';
COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail of all system activities';
COMMENT ON TABLE api_keys IS 'API keys for service-to-service authentication';

COMMENT ON COLUMN users.role IS 'User role: super_admin, admin, power_user, user, read_only';
COMMENT ON COLUMN users.permissions IS 'Additional granular permissions in JSON format';
COMMENT ON COLUMN services.config IS 'Service-specific configuration in JSON format';
COMMENT ON COLUMN audit_logs.changes IS 'Before/after diff of changes in JSON format';
