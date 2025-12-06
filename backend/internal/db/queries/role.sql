-- internal/db/queries/role.sql
-- SQL queries for role and permission operations (used by sqlc)

-- ==================== Roles ====================

-- name: GetRoleByID :one
SELECT * FROM roles WHERE id = $1 LIMIT 1;

-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = $1 LIMIT 1;

-- name: ListRoles :many
SELECT * FROM roles ORDER BY id;

-- name: CreateRole :one
INSERT INTO roles (name, description)
VALUES ($1, $2)
RETURNING *;

-- name: UpdateRole :one
UPDATE roles
SET description = $2, updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: DeleteRole :exec
DELETE FROM roles WHERE id = $1;

-- ==================== Permissions ====================

-- name: GetPermissionByID :one
SELECT * FROM permissions WHERE id = $1 LIMIT 1;

-- name: GetPermissionByName :one
SELECT * FROM permissions WHERE name = $1 LIMIT 1;

-- name: ListPermissions :many
SELECT * FROM permissions ORDER BY id;

-- name: CreatePermission :one
INSERT INTO permissions (name, description)
VALUES ($1, $2)
RETURNING *;

-- name: UpdatePermission :one
UPDATE permissions
SET description = $2, updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: DeletePermission :exec
DELETE FROM permissions WHERE id = $1;

-- ==================== Role Permissions ====================

-- name: GetRolePermissions :many
SELECT p.*
FROM permissions p
JOIN role_permissions rp ON p.id = rp.permission_id
WHERE rp.role_id = $1
ORDER BY p.name;

-- name: AssignPermissionToRole :one
INSERT INTO role_permissions (role_id, permission_id)
VALUES ($1, $2)
ON CONFLICT (role_id, permission_id) DO NOTHING
RETURNING *;

-- name: RemovePermissionFromRole :exec
DELETE FROM role_permissions
WHERE role_id = $1 AND permission_id = $2;

-- name: RemoveAllPermissionsFromRole :exec
DELETE FROM role_permissions WHERE role_id = $1;

-- ==================== User Roles ====================

-- name: GetUserRoles :many
SELECT r.*
FROM roles r
JOIN user_roles ur ON r.id = ur.role_id
WHERE ur.user_id = $1
ORDER BY r.name;

-- name: AssignRoleToUser :one
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
ON CONFLICT (user_id, role_id) DO NOTHING
RETURNING *;

-- name: RemoveRoleFromUser :exec
DELETE FROM user_roles
WHERE user_id = $1 AND role_id = $2;

-- name: RemoveAllRolesFromUser :exec
DELETE FROM user_roles WHERE user_id = $1;

-- name: GetUsersWithRole :many
SELECT u.*
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
WHERE ur.role_id = $1
ORDER BY u.username;

