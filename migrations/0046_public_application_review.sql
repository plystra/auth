-- +goose Up

-- The published manifest is the effective maximum. A public application starts
-- with no effective permissions until an operator approves its pending request.
ALTER TABLE applications
    ADD COLUMN review_status text NOT NULL DEFAULT 'not_required'
        CHECK (review_status IN ('not_required', 'pending', 'approved', 'rejected')),
    ADD COLUMN pending_manifest_permissions jsonb
        CHECK (pending_manifest_permissions IS NULL OR jsonb_typeof(pending_manifest_permissions) = 'array'),
    ADD CONSTRAINT applications_review_visibility_check CHECK (
        (visibility = 'private' AND review_status = 'not_required' AND pending_manifest_permissions IS NULL)
        OR
        (visibility = 'public' AND review_status <> 'not_required')
    );

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
