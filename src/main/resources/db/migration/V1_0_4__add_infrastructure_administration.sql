INSERT INTO auth.role (id, name)
VALUES (gen_random_uuid(), 'INFRASTRUCTURE_INTERNAL')
ON CONFLICT (name) DO NOTHING;

CREATE TABLE auth.audit_event (
    id UUID PRIMARY KEY,
    actor_username VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id VARCHAR(255) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_event_created_at ON auth.audit_event (created_at DESC);
CREATE INDEX idx_audit_event_target ON auth.audit_event (target_type, target_id, created_at DESC);
