-- ENUM TYPES
CREATE TYPE login_result AS ENUM ('success', 'fail');
CREATE TYPE auth_method AS ENUM ('email', 'sms', 'authenticator');
CREATE TYPE share_status AS ENUM ('active', 'pending', 'fail');

-- FUNCTION TO AUTO-UPDATE updated_at FIELD
CREATE OR REPLACE FUNCTION update_timestamp()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- TABLES --

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    image_url TEXT NOT NULL,
    email_hash TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    mfa INTEGER NOT NULL DEFAULT 0 CHECK (mfa >= 0),
    mfa_end TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auth_history (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    auth_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    result login_result NOT NULL,
    location TEXT NOT NULL,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    account_lock_until TIMESTAMPTZ
);

CREATE TABLE user_passwords (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    note TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    last_use TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE email_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_verify (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    method auth_method NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    otp_secret TEXT NOT NULL,
    last_verified TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, method)
);

CREATE TABLE credential_sharing (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id UUID REFERENCES user_passwords(id) ON DELETE CASCADE,
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
    shared_id UUID REFERENCES users(id) ON DELETE CASCADE,
    status share_status NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- INDEXES --

CREATE INDEX idx_account_users_email ON users (email);
CREATE INDEX idx_login_records_user_time ON auth_history (user_id, auth_timestamp DESC);
CREATE INDEX idx_credentials_user_service ON user_passwords (user_id, description);
CREATE INDEX idx_email_tokens_token ON email_tokens (token);
CREATE INDEX idx_user_auth_methods_active ON user_auth (user_id, is_active);
CREATE INDEX idx_sharing_owner ON credential_sharing (owner_id);
CREATE INDEX idx_sharing_shared ON credential_sharing (shared_id);

-- TRIGGERS --

CREATE TRIGGER trigger_users_updated
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trigger_credentials_updated
    BEFORE UPDATE ON user_passwords
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trigger_verify_methods_updated
    BEFORE UPDATE ON user_verify
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trigger_sharing_updated
    BEFORE UPDATE ON credential_sharing
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();
