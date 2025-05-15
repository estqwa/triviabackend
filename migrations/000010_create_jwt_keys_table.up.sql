    -- migrations/{timestamp}_create_jwt_keys_table.up.sql
    CREATE TABLE IF NOT EXISTS jwt_keys (
        id VARCHAR(100) PRIMARY KEY,
        key TEXT NOT NULL, -- Store encrypted key
        algorithm VARCHAR(50) NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMPTZ NOT NULL,
        rotated_at TIMESTAMPTZ,
        last_used_at TIMESTAMPTZ -- Optional, can be updated on key usage
    );

    -- Add indexes for faster lookups
    CREATE INDEX IF NOT EXISTS idx_jwt_keys_is_active ON jwt_keys (is_active);
    CREATE INDEX IF NOT EXISTS idx_jwt_keys_expires_at ON jwt_keys (expires_at);
    CREATE INDEX IF NOT EXISTS idx_jwt_keys_rotated_at ON jwt_keys (rotated_at);
    CREATE INDEX IF NOT EXISTS idx_jwt_keys_created_at ON jwt_keys (created_at);