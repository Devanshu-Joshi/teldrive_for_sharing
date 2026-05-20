-- +goose Up
-- +goose StatementBegin
DELETE FROM teldrive.uploads u1 USING teldrive.uploads u2
WHERE u1.part_id < u2.part_id
  AND u1.upload_id = u2.upload_id
  AND u1.part_no = u2.part_no;

ALTER TABLE teldrive.uploads ADD CONSTRAINT unique_upload_part UNIQUE (upload_id, part_no);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE teldrive.uploads DROP CONSTRAINT IF EXISTS unique_upload_part;
-- +goose StatementEnd
