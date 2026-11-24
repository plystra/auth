-- +goose Up
CREATE INDEX directory_groups_active_name_idx
    ON directory_groups (directory_id, lower(display_name), id)
    WHERE deleted_at IS NULL;

-- +goose Down
DROP INDEX directory_groups_active_name_idx;
