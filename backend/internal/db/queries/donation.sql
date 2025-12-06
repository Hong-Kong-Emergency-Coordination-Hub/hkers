-- internal/db/queries/donation.sql
-- SQL queries for donation operations (used by sqlc)

-- name: GetDonationByID :one
SELECT * FROM donations WHERE id = $1 LIMIT 1;

-- name: GetDonationByDeliveryCode :one
SELECT * FROM donations WHERE delivery_code = $1 LIMIT 1;

-- name: ListDonations :many
SELECT * FROM donations
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDonationsByStatus :many
SELECT * FROM donations
WHERE status = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListDonationsByDonor :many
SELECT * FROM donations
WHERE donor_id = $1
ORDER BY created_at DESC;

-- name: ListDonationsByStation :many
SELECT * FROM donations
WHERE station_id = $1
ORDER BY created_at DESC;

-- name: CountDonations :one
SELECT COUNT(*) FROM donations;

-- name: CountDonationsByStatus :one
SELECT COUNT(*) FROM donations WHERE status = $1;

-- name: CreateDonation :one
INSERT INTO donations (donor_id, station_id, supplies, delivery_code, status, estimated_delivery)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UpdateDonationStatus :one
UPDATE donations
SET status = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: UpdateDonation :one
UPDATE donations
SET supplies = $2,
    status = $3,
    estimated_delivery = $4,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: DeleteDonation :exec
DELETE FROM donations WHERE id = $1;

-- name: GetDonationWithDetails :one
SELECT 
    d.*,
    u.username as donor_username,
    u.email as donor_email
FROM donations d
LEFT JOIN users u ON d.donor_id = u.id
WHERE d.id = $1;

