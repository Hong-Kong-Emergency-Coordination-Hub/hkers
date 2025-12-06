-- internal/db/queries/audit.sql
-- SQL queries for RBAC audit log operations (used by sqlc)

-- name: GetAuditLogByID :one
SELECT * FROM rbac_audit_logs WHERE id = $1 LIMIT 1;

-- name: ListAuditLogs :many
SELECT * FROM rbac_audit_logs
ORDER BY changed_at DESC
LIMIT $1 OFFSET $2;

-- name: ListAuditLogsByTable :many
SELECT * FROM rbac_audit_logs
WHERE table_name = $1
ORDER BY changed_at DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditLogsByAction :many
SELECT * FROM rbac_audit_logs
WHERE action = $1
ORDER BY changed_at DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditLogsByUser :many
SELECT * FROM rbac_audit_logs
WHERE changed_by = $1
ORDER BY changed_at DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditLogsInDateRange :many
SELECT * FROM rbac_audit_logs
WHERE changed_at >= $1 AND changed_at <= $2
ORDER BY changed_at DESC
LIMIT $3 OFFSET $4;

-- name: CountAuditLogs :one
SELECT COUNT(*) FROM rbac_audit_logs;

-- name: CreateAuditLog :one
INSERT INTO rbac_audit_logs (table_name, action, old_data, new_data, changed_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: DeleteOldAuditLogs :exec
DELETE FROM rbac_audit_logs WHERE changed_at < $1;

