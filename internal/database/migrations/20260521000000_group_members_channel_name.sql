-- +goose Up
-- +goose StatementBegin
ALTER TABLE teldrive.group_members
    ADD COLUMN IF NOT EXISTS channel_name text NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE teldrive.group_members
    DROP COLUMN IF EXISTS channel_name;
-- +goose StatementEnd
