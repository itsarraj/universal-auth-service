-- Universal Auth Service Database Migration
-- Run this script to set up the complete authentication system

-- =====================================================
-- USERS TABLE
-- Stores core user information and authentication data
-- =====================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('user', 'admin', 'moderator')),
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    password_reset_token VARCHAR(255),
    password_reset_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_email_verification_token ON users(email_verification_token);
CREATE INDEX IF NOT EXISTS idx_users_password_reset_token ON users(password_reset_token);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- =====================================================
-- REFRESH TOKENS TABLE
-- Stores refresh tokens for JWT token rotation
-- =====================================================

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL, -- Hashed for security
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- =====================================================
-- TOKEN BLACKLIST TABLE
-- Stores revoked/invalidated tokens
-- =====================================================

CREATE TABLE IF NOT EXISTS token_blacklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_token_blacklist_token_hash ON token_blacklist(token_hash);
CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires_at ON token_blacklist(expires_at);

-- =====================================================
-- USER SESSIONS TABLE (Optional - for advanced session management)
-- =====================================================

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_session_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);

-- =====================================================
-- AUDIT LOG TABLE (Optional - for compliance and monitoring)
-- =====================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL, -- 'login', 'logout', 'password_change', etc.
    ip_address INET,
    user_agent TEXT,
    metadata JSONB, -- Additional context data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- =====================================================
-- TRIGGERS FOR AUTOMATIC TIMESTAMPS
-- =====================================================

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for users table
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- CLEANUP FUNCTIONS
-- =====================================================

-- Function to clean up expired tokens and sessions
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Delete expired refresh tokens
    DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP;

    -- Delete expired blacklisted tokens
    DELETE FROM token_blacklist WHERE expires_at < CURRENT_TIMESTAMP;

    -- Delete expired sessions
    DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- SAMPLE DATA (For Development/Testing)
-- =====================================================

-- Insert a test admin user (password: "admin123")
-- Password hash generated with bcrypt
INSERT INTO users (id, email, password_hash, name, role, email_verified, created_at, updated_at)
VALUES (
    '550e8400-e29b-41d4-a716-446655440000',
    'admin@example.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/7LpMh7UeO8QKdJcO', -- bcrypt hash for "admin123"
    'System Administrator',
    'admin',
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
) ON CONFLICT (email) DO NOTHING;

-- Insert a test regular user (password: "user123")
INSERT INTO users (id, email, password_hash, name, role, email_verified, created_at, updated_at)
VALUES (
    '550e8400-e29b-41d4-a716-446655440001',
    'user@example.com',
    '$2b$12$8K2LZ5VzEJ8xqv9XKvj7Be3Q0vBH8I8qQkJcKvJcKvJcKvJcKvJcK', -- bcrypt hash for "user123"
    'Test User',
    'user',
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
) ON CONFLICT (email) DO NOTHING;

-- =====================================================
-- USEFUL QUERIES FOR MONITORING
-- =====================================================

-- Count active users
-- SELECT COUNT(*) as active_users FROM users WHERE email_verified = true;

-- Count recent logins (last 24 hours)
-- SELECT COUNT(*) as recent_logins FROM audit_logs
-- WHERE action = 'login' AND created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours';

-- Count active sessions
-- SELECT COUNT(*) as active_sessions FROM user_sessions WHERE expires_at > CURRENT_TIMESTAMP;

-- Get login attempts by IP (for security monitoring)
-- SELECT ip_address, COUNT(*) as attempts, MAX(created_at) as last_attempt
-- FROM audit_logs WHERE action = 'login_failed'
-- GROUP BY ip_address ORDER BY attempts DESC LIMIT 10;

-- =====================================================
-- PERFORMANCE OPTIMIZATIONS
-- =====================================================

-- Analyze tables for query optimization
ANALYZE users;
ANALYZE refresh_tokens;
ANALYZE token_blacklist;
ANALYZE user_sessions;
ANALYZE audit_logs;

-- =====================================================
-- COMMENTS
-- =====================================================

COMMENT ON TABLE users IS 'Core user accounts with authentication data';
COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens for secure token rotation';
COMMENT ON TABLE token_blacklist IS 'Revoked tokens to prevent reuse';
COMMENT ON TABLE user_sessions IS 'Active user sessions for advanced session management';
COMMENT ON TABLE audit_logs IS 'Audit trail for security and compliance';

COMMENT ON COLUMN users.password_hash IS 'Bcrypt hashed password';
COMMENT ON COLUMN users.email_verification_token IS 'Token for email verification process';
COMMENT ON COLUMN users.password_reset_token IS 'Token for password reset process';
COMMENT ON COLUMN refresh_tokens.token_hash IS 'Hashed refresh token for security';
COMMENT ON COLUMN token_blacklist.token_hash IS 'Hashed blacklisted token';

-- =====================================================
-- MIGRATION COMPLETE
-- =====================================================

-- Run this to verify the setup
DO $$
BEGIN
    RAISE NOTICE 'Database migration completed successfully!';
    RAISE NOTICE 'Created tables: users, refresh_tokens, token_blacklist, user_sessions, audit_logs';
    RAISE NOTICE 'Created indexes and triggers for optimal performance';
    RAISE NOTICE 'Inserted sample admin and user accounts';
    RAISE NOTICE 'Ready for authentication system!';
END $$;