-- ENUM TYPES
CREATE TYPE login_result AS ENUM ('success', 'fail');
CREATE TYPE auth_method AS ENUM ('email', 'sms', 'authenticator');
CREATE TYPE share_status AS ENUM ('success', 'pending', 'fail');

-- FUNCTION TO AUTO-UPDATE updated_at FIELD
CREATE OR REPLACE FUNCTION update_timestamp()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- FUNCTION TO DELETE SHARING ON SUCCESS
CREATE OR REPLACE FUNCTION delete_successful_sharing()
    RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'success' THEN
        DELETE FROM password_sharing WHERE id = NEW.id;
    END IF;
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
    public_key TEXT NOT NULL,
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
    location TEXT NOT NULL
);

CREATE TABLE user_password (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    note TEXT NOT NULL,
    password TEXT NOT NULL,
    description_hash TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT TRUE,
    last_use TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, description_hash)
);

CREATE TABLE email_token (
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

CREATE TABLE password_sharing (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    password_id UUID REFERENCES user_password(id) ON DELETE CASCADE,
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
    shared_id UUID REFERENCES users(id) ON DELETE CASCADE,
    public_key_hash TEXT NOT NULL,
    status share_status NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- INDEXES --

-- Recherche rapide d’un utilisateur par email (login, register, validation)
CREATE INDEX idx_account_users_email ON users (email);
-- Accès rapide à tous les logs d’un utilisateur (ex: /history)
CREATE INDEX idx_auth_history_user ON auth_history (user_id);
-- Récupération rapide des mots de passe d’un utilisateur (ex: /passwords)
CREATE INDEX idx_password_user ON user_password (user_id);
-- Optimisé pour afficher les derniers logs en haut (ORDER BY auth_timestamp DESC)
CREATE INDEX idx_login_records_user_time ON auth_history (user_id, auth_timestamp DESC);
-- Vérifie efficacement l’unicité d’une description pour un utilisateur
CREATE INDEX idx_password_user_service ON user_password (user_id, description_hash);
-- Permet de valider un token rapidement (vérification email)
CREATE INDEX idx_email_token_token ON email_token (token);
-- Récupération rapide des méthodes MFA actives pour un utilisateur
CREATE INDEX idx_user_auth_methods_active ON user_verify (user_id, is_active);
-- Permet d’afficher rapidement les partages faits par un utilisateur
CREATE INDEX idx_sharing_owner ON password_sharing (owner_id);
-- Permet d’afficher rapidement les partages reçus par un utilisateur
CREATE INDEX idx_sharing_shared ON password_sharing (shared_id);

-- TRIGGERS --

-- Met automatiquement à jour le champ `updated_at` lors d’une modification d’un utilisateur
CREATE TRIGGER trigger_users_updated
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();
-- Met automatiquement à jour `updated_at` quand un mot de passe est modifié
CREATE TRIGGER trigger_password_updated
    BEFORE UPDATE ON user_password
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();
-- Met à jour `updated_at` lorsqu’une méthode MFA est modifiée (activation, dernière vérification)
CREATE TRIGGER trigger_verify_methods_updated
    BEFORE UPDATE ON user_verify
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();
-- Met à jour `updated_at` si un partage de mot de passe change (statut, expiration, etc.)
CREATE TRIGGER trigger_sharing_updated
    BEFORE UPDATE ON password_sharing
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();
-- TRIGGER POUR EFFACER LE SHARING QUAND status = 'success'
CREATE TRIGGER trigger_sharing_auto_delete_success
    AFTER UPDATE ON password_sharing
    FOR EACH ROW
    WHEN (NEW.status = 'success')
EXECUTE FUNCTION delete_successful_sharing();