-- internal/db/queries/user.sql
-- SQL queries for user operations (used by sqlc)

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 LIMIT 1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1 LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 LIMIT 1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: CreateUser :one
INSERT INTO users (oidc_sub, username, email, trust_points)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: UpdateUser :one
UPDATE users
SET username = $2, email = $3
WHERE id = $1
RETURNING *;

-- name: UpdateUserTrustPoints :one
UPDATE users
SET trust_points = trust_points + $2
WHERE id = $1
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: GetUserWithRoles :many
SELECT 
    u.*,
    r.id as role_id,
    r.name as role_name,
    r.description as role_description
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.id = $1;

-- name: GetUserPermissions :many
SELECT DISTINCT p.name
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN role_permissions rp ON ur.role_id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id
WHERE u.id = $1;

-- name: CheckUserPermission :one
SELECT EXISTS (
    SELECT 1
    FROM users u
    JOIN user_roles ur ON u.id = ur.user_id
    JOIN role_permissions rp ON ur.role_id = rp.role_id
    JOIN permissions p ON rp.permission_id = p.id
    WHERE u.id = $1 AND p.name = $2
) AS has_permission;

-- name: GetUserByOIDCSub :one
-- Find a user by their OIDC subject identifier
SELECT * FROM users WHERE oidc_sub = $1 LIMIT 1;

-- name: GetActiveUserByOIDCSub :one
-- Find an active user by their OIDC subject identifier (for login validation)
SELECT * FROM users WHERE oidc_sub = $1 AND is_active = TRUE LIMIT 1;

-- name: CreateUserFromOIDC :one
-- Create a new user from OIDC authentication (inactive by default - requires admin approval)
INSERT INTO users (oidc_sub, username, email, is_active, trust_points)
VALUES ($1, $2, $3, FALSE, 0)
RETURNING *;

-- name: ActivateUser :one
-- Activate a user (admin only)
UPDATE users SET is_active = TRUE WHERE id = $1 RETURNING *;

-- name: DeactivateUser :one
-- Deactivate a user (admin only) - blocks login without deleting data
UPDATE users SET is_active = FALSE WHERE id = $1 RETURNING *;

-- name: UpdateUserOIDCSub :one
-- Link an existing user to their OIDC account
UPDATE users SET oidc_sub = $2 WHERE id = $1 RETURNING *;