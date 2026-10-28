CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    email_normalized TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    email_verified_at TIMESTAMPTZ,
    auth_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX users_status_idx ON users(status) WHERE deleted_at IS NULL;

CREATE TABLE roles (
    code TEXT PRIMARY KEY CHECK (code IN ('student', 'verifier', 'program_manager', 'admin', 'partner_viewer', 'mentor')),
    description TEXT NOT NULL
);
INSERT INTO roles(code, description) VALUES
 ('student', 'Registered student'),
 ('verifier', 'Reviews and decides proof verification'),
 ('program_manager', 'Manages programs, events, opportunities, content and reports'),
 ('admin', 'Full administrative access including staff roles and data requests'),
 ('partner_viewer', 'Read-only anonymised partner reporting'),
 ('mentor', 'Mentor/speaker access, reserved for a later phase')
ON CONFLICT (code) DO NOTHING;

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_code TEXT NOT NULL REFERENCES roles(code),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_code)
);
CREATE INDEX user_roles_role_idx ON user_roles(role_code, user_id);

CREATE TABLE student_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    whatsapp_number TEXT,
    school_name TEXT,
    state TEXT,
    faculty TEXT,
    department TEXT,
    course TEXT,
    level TEXT,
    age_range TEXT CHECK (age_range IS NULL OR age_range IN ('under_18', '18_20', '21_24', '25_29', '30_plus', 'prefer_not_to_say')),
    matriculation_number TEXT,
    interests TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX student_profiles_school_idx ON student_profiles(school_name);
CREATE INDEX student_profiles_course_idx ON student_profiles(course);

CREATE TABLE consent_documents (
    consent_type TEXT NOT NULL CHECK (consent_type IN ('privacy_notice', 'terms')),
    version TEXT NOT NULL,
    wording_snapshot TEXT NOT NULL,
    is_current BOOLEAN NOT NULL DEFAULT false,
    published_by UUID REFERENCES users(id) ON DELETE SET NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(consent_type, version)
);
CREATE UNIQUE INDEX consent_documents_current_idx ON consent_documents(consent_type) WHERE is_current = true;

CREATE TABLE consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    consent_type TEXT NOT NULL CHECK (consent_type IN ('privacy_notice', 'terms', 'publicity_media', 'whatsapp_messages', 'email_messages')),
    wording_version TEXT NOT NULL,
    wording_snapshot TEXT NOT NULL,
    accepted BOOLEAN NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address INET,
    user_agent TEXT,
    anonymised_at TIMESTAMPTZ
);
CREATE INDEX consents_user_type_idx ON consents(user_id, consent_type, accepted_at DESC);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_refreshed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT,
    ip_address INET
);
CREATE INDEX user_sessions_user_idx ON user_sessions(user_id, expires_at DESC);
CREATE INDEX user_sessions_active_idx ON user_sessions(id) WHERE revoked_at IS NULL;

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE opportunities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    summary TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'general',
    official_url TEXT NOT NULL,
    application_deadline TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    partner_name TEXT,
    value_ngn BIGINT CHECK (value_ngn IS NULL OR value_ngn >= 0),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX opportunities_public_idx ON opportunities(status, application_deadline, created_at DESC);
CREATE INDEX opportunities_category_idx ON opportunities(category, status);

CREATE TABLE programs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    school_name TEXT,
    state TEXT,
    start_at TIMESTAMPTZ,
    end_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'completed', 'archived')),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX programs_status_idx ON programs(status, start_at DESC);

CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ,
    checkin_opens_at TIMESTAMPTZ,
    checkin_closes_at TIMESTAMPTZ,
    qr_token_hash BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'live', 'completed', 'cancelled')),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (ends_at IS NULL OR ends_at >= starts_at),
    CHECK (checkin_closes_at IS NULL OR checkin_opens_at IS NULL OR checkin_closes_at >= checkin_opens_at)
);
CREATE INDEX events_program_date_idx ON events(program_id, starts_at);

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    opportunity_id UUID NOT NULL REFERENCES opportunities(id) ON DELETE RESTRICT,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    email TEXT NOT NULL,
    email_normalized TEXT NOT NULL,
    stage TEXT NOT NULL DEFAULT 'registered' CHECK (stage IN ('registered', 'guided', 'activated', 'completed', 'verified', 'engaged')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'withdrawn', 'deleted')),
    registration_snapshot JSONB NOT NULL,
    guest_access_token_hash BYTEA,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    clicked_through_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX applications_user_opportunity_unique ON applications(user_id, opportunity_id) WHERE user_id IS NOT NULL AND status <> 'deleted';
CREATE UNIQUE INDEX applications_guest_opportunity_unique ON applications(email_normalized, opportunity_id) WHERE user_id IS NULL AND status <> 'deleted';
CREATE INDEX applications_opportunity_stage_idx ON applications(opportunity_id, stage, registered_at DESC);
CREATE INDEX applications_user_idx ON applications(user_id, registered_at DESC);
CREATE INDEX applications_email_idx ON applications(email_normalized);

ALTER TABLE consents ADD COLUMN application_id UUID REFERENCES applications(id) ON DELETE SET NULL;
ALTER TABLE consents ADD COLUMN email_normalized TEXT;
ALTER TABLE consents ADD CONSTRAINT consent_subject_check CHECK (user_id IS NOT NULL OR application_id IS NOT NULL OR email_normalized IS NOT NULL OR anonymised_at IS NOT NULL);
CREATE INDEX consents_application_idx ON consents(application_id, accepted_at DESC);

CREATE TABLE event_checkins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    checked_in_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    method TEXT NOT NULL CHECK (method IN ('qr', 'paper_sheet', 'staff_manual')),
    recorded_by UUID REFERENCES users(id) ON DELETE SET NULL,
    note TEXT,
    UNIQUE(event_id, user_id)
);
CREATE INDEX checkins_event_time_idx ON event_checkins(event_id, checked_in_at);
CREATE INDEX checkins_user_time_idx ON event_checkins(user_id, checked_in_at DESC);

CREATE TABLE proofs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (kind IN ('activation_screenshot', 'certificate', 'completion_evidence', 'other')),
    original_filename TEXT NOT NULL,
    mime_type TEXT NOT NULL CHECK (mime_type IN ('application/pdf', 'image/jpeg', 'image/png')),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 5242880),
    object_key TEXT NOT NULL,
    sha256 BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewer_note TEXT,
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMPTZ,
    delete_after TIMESTAMPTZ,
    storage_deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX proofs_queue_idx ON proofs(status, created_at) WHERE status = 'pending';
CREATE INDEX proofs_application_idx ON proofs(application_id, created_at DESC);
CREATE INDEX proofs_retention_idx ON proofs(delete_after) WHERE delete_after IS NOT NULL AND storage_deleted_at IS NULL;

CREATE TABLE verification_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID NOT NULL REFERENCES proofs(id) ON DELETE RESTRICT,
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    verifier_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    note TEXT,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX verification_decisions_application_idx ON verification_decisions(application_id, decided_at DESC);

CREATE TABLE surveys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    survey_type TEXT NOT NULL CHECK (survey_type IN ('completion', 'day_30', 'day_90', 'day_180', 'event_feedback')),
    answers JSONB NOT NULL,
    usefulness_rating SMALLINT CHECK (usefulness_rating IS NULL OR usefulness_rating BETWEEN 1 AND 5),
    recommend BOOLEAN,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(application_id, survey_type)
);
CREATE INDEX surveys_submitted_idx ON surveys(survey_type, submitted_at DESC);

CREATE TABLE activity_days (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    activity_date DATE NOT NULL,
    actions_count INTEGER NOT NULL DEFAULT 1 CHECK (actions_count > 0),
    last_action_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(user_id, activity_date)
);
CREATE INDEX activity_days_date_idx ON activity_days(activity_date);

CREATE TABLE partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    organisation_type TEXT NOT NULL DEFAULT 'sponsor',
    contact_name TEXT,
    email TEXT,
    phone TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_created_idx ON audit_logs(created_at DESC);
CREATE INDEX audit_logs_actor_idx ON audit_logs(actor_user_id, created_at DESC);
CREATE INDEX audit_logs_entity_idx ON audit_logs(entity_type, entity_id, created_at DESC);

CREATE TABLE email_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient TEXT NOT NULL,
    template TEXT NOT NULL,
    payload JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX email_outbox_pending_idx ON email_outbox(available_at, created_at) WHERE sent_at IS NULL;

CREATE TABLE idempotency_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key TEXT NOT NULL,
    actor_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    request_hash BYTEA NOT NULL,
    response_status INTEGER,
    response_body JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE(key, actor_user_id)
);
CREATE INDEX idempotency_expiry_idx ON idempotency_keys(expires_at);

CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX email_verification_user_idx ON email_verification_tokens(user_id, created_at DESC);

CREATE TABLE program_opportunities (
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    opportunity_id UUID NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(program_id, opportunity_id)
);
CREATE INDEX program_opportunities_opportunity_idx ON program_opportunities(opportunity_id, program_id);
