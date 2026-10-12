ALTER TABLE auth.oauth2_registered_client ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE auth.audit_event ADD COLUMN correlation_id VARCHAR(36);

CREATE FUNCTION auth.reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Audit events are append-only';
END;
$$;

CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON auth.audit_event
FOR EACH ROW EXECUTE FUNCTION auth.reject_audit_mutation();
