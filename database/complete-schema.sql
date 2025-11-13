-- Complete remaining PostgreSQL schema
-- Adds audit_logs and api_keys tables

-- ============================================================================
-- AUDIT_LOGS TABLE (comprehensive activity tracking)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
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
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_changes ON audit_logs USING GIN(changes);  -- JSON index

-- ============================================================================
-- API_KEYS TABLE (for service-to-service authentication - Phase 3)
-- ============================================================================
CREATE TABLE IF NOT EXISTS api_keys (
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
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at) WHERE expires_at IS NOT NULL;

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
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail of all system activities';
COMMENT ON TABLE api_keys IS 'API keys for service-to-service authentication';

COMMENT ON COLUMN audit_logs.changes IS 'Before/after diff of changes in JSON format';
