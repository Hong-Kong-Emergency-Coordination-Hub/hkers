-- internal/db/queries/checkin.sql
-- SQL queries for check-in operations (used by sqlc)

-- name: GetCheckinByID :one
SELECT * FROM checkins WHERE id = $1 LIMIT 1;

-- name: GetCheckinByUserAndStation :one
SELECT * FROM checkins
WHERE user_id = $1 AND station_id = $2
LIMIT 1;

-- name: ListCheckins :many
SELECT * FROM checkins
ORDER BY checkin_time DESC
LIMIT $1 OFFSET $2;

-- name: ListCheckinsByStation :many
SELECT * FROM checkins
WHERE station_id = $1
ORDER BY checkin_time DESC;

-- name: ListCheckinsByUser :many
SELECT * FROM checkins
WHERE user_id = $1
ORDER BY checkin_time DESC;

-- name: CountCheckinsByStation :one
SELECT COUNT(*) FROM checkins WHERE station_id = $1;

-- name: CreateCheckin :one
INSERT INTO checkins (user_id, station_id, checkin_location, notes)
VALUES ($1, $2, ST_SetSRID(ST_MakePoint($3, $4), 4326)::geography, $5)
RETURNING *;

-- name: CreateCheckinWithoutLocation :one
INSERT INTO checkins (user_id, station_id, notes)
VALUES ($1, $2, $3)
RETURNING *;

-- name: UpdateCheckinNotes :one
UPDATE checkins
SET notes = $2
WHERE id = $1
RETURNING *;

-- name: DeleteCheckin :exec
DELETE FROM checkins WHERE id = $1;

-- name: HasUserCheckedInAtStation :one
SELECT EXISTS (
    SELECT 1 FROM checkins
    WHERE user_id = $1 AND station_id = $2
) AS has_checked_in;

-- name: GetCheckinWithDetails :one
SELECT 
    c.*,
    u.username,
    u.email
FROM checkins c
JOIN users u ON c.user_id = u.id
WHERE c.id = $1;

-- name: ListCheckinsWithUserDetails :many
SELECT 
    c.*,
    u.username,
    u.email
FROM checkins c
JOIN users u ON c.user_id = u.id
WHERE c.station_id = $1
ORDER BY c.checkin_time DESC;

