-- internal/db/queries/station.sql
-- SQL queries for supply station operations (used by sqlc)

-- ==================== Supply Stations ====================

-- name: GetStationByID :one
SELECT * FROM supply_stations WHERE id = $1 LIMIT 1;

-- name: ListStations :many
SELECT * FROM supply_stations
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: ListVerifiedStations :many
SELECT * FROM supply_stations
WHERE is_verified = TRUE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: ListUnverifiedStations :many
SELECT * FROM supply_stations
WHERE is_verified = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountStations :one
SELECT COUNT(*) FROM supply_stations;

-- name: CountVerifiedStations :one
SELECT COUNT(*) FROM supply_stations WHERE is_verified = TRUE;

-- name: ListStationsByUser :many
SELECT * FROM supply_stations
WHERE registered_by = $1
ORDER BY created_at DESC;

-- name: CreateStation :one
INSERT INTO supply_stations (registered_by, location, verification_threshold)
VALUES ($1, ST_SetSRID(ST_MakePoint($2, $3), 4326)::geography, $4)
RETURNING *;

-- name: UpdateStation :one
UPDATE supply_stations
SET location = ST_SetSRID(ST_MakePoint($2, $3), 4326)::geography,
    verification_threshold = $4,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: IncrementVerificationCount :one
UPDATE supply_stations
SET verification_count = verification_count + 1,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: SetStationVerified :one
UPDATE supply_stations
SET is_verified = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: DeleteStation :exec
DELETE FROM supply_stations WHERE id = $1;

-- name: FindNearbyStations :many
SELECT *,
    ST_Distance(location, ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography) as distance_meters
FROM supply_stations
WHERE ST_DWithin(location, ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography, $3)
ORDER BY distance_meters
LIMIT $4;

-- name: FindNearbyVerifiedStations :many
SELECT *,
    ST_Distance(location, ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography) as distance_meters
FROM supply_stations
WHERE is_verified = TRUE
  AND ST_DWithin(location, ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography, $3)
ORDER BY distance_meters
LIMIT $4;

-- ==================== Supply Needs ====================

-- name: GetSupplyNeedByID :one
SELECT * FROM supply_needs WHERE id = $1 LIMIT 1;

-- name: ListSupplyNeedsByStation :many
SELECT * FROM supply_needs
WHERE station_id = $1
ORDER BY urgency_level DESC, created_at DESC;

-- name: CreateSupplyNeed :one
INSERT INTO supply_needs (station_id, supply_type, quantity_needed, description, urgency_level)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpdateSupplyNeed :one
UPDATE supply_needs
SET supply_type = $2,
    quantity_needed = $3,
    description = $4,
    urgency_level = $5,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: DeleteSupplyNeed :exec
DELETE FROM supply_needs WHERE id = $1;

-- name: DeleteSupplyNeedsByStation :exec
DELETE FROM supply_needs WHERE station_id = $1;

