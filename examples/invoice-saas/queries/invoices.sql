-- name: CreateInvoice :one
INSERT INTO invoices (id, space_id, group_id, amount_cents, currency)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(group_id), sqlc.arg(amount_cents), sqlc.arg(currency))
RETURNING *;

-- name: GetInvoice :one
SELECT * FROM invoices WHERE id = sqlc.arg(id);

-- name: ApproveInvoice :one
UPDATE invoices SET status = 'approved', version = version + 1,
    approved_by = sqlc.arg(member_id), approved_at = now()
WHERE id = sqlc.arg(id) AND version = sqlc.arg(expected_version) AND status = 'draft'
RETURNING *;
