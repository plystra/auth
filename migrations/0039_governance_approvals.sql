-- +goose Up

ALTER TABLE approval_requests
    ADD COLUMN kind text NOT NULL DEFAULT 'business'
        CHECK (kind IN ('business', 'governance')),
    ADD COLUMN operation text,
    ADD COLUMN request_details jsonb;

ALTER TABLE approval_requests
    ADD CONSTRAINT approval_requests_governance_details_check
    CHECK ((kind = 'business' AND operation IS NULL AND request_details IS NULL)
        OR (kind = 'governance' AND operation IS NOT NULL AND operation <> '' AND request_details IS NOT NULL));

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
