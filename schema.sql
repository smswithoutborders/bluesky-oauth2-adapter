-- Table for storing OAuth sessions
CREATE TABLE IF NOT EXISTS oauth_sessions (
    request_identifier TEXT PRIMARY KEY,
    dpop_private_jwk TEXT NOT NULL,
    authserver_iss TEXT NOT NULL,
    dpop_authserver_nonce TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
