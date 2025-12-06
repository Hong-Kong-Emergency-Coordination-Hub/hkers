-- internal/db/queries/news.sql
-- SQL queries for news operations (used by sqlc)

-- name: GetNewsByID :one
SELECT * FROM news WHERE id = $1 LIMIT 1;

-- name: ListNews :many
SELECT * FROM news
ORDER BY published_at DESC NULLS LAST, fetched_at DESC
LIMIT $1 OFFSET $2;

-- name: ListNewsBySource :many
SELECT * FROM news
WHERE source = $1
ORDER BY published_at DESC NULLS LAST, fetched_at DESC
LIMIT $2 OFFSET $3;

-- name: ListRecentNews :many
SELECT * FROM news
WHERE published_at >= $1
ORDER BY published_at DESC NULLS LAST
LIMIT $2;

-- name: CountNews :one
SELECT COUNT(*) FROM news;

-- name: CountNewsBySource :one
SELECT COUNT(*) FROM news WHERE source = $1;

-- name: CreateNews :one
INSERT INTO news (source, title, content, url, published_at, relevant_to)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UpdateNews :one
UPDATE news
SET source = $2,
    title = $3,
    content = $4,
    url = $5,
    published_at = $6,
    relevant_to = $7
WHERE id = $1
RETURNING *;

-- name: DeleteNews :exec
DELETE FROM news WHERE id = $1;

-- name: DeleteOldNews :exec
DELETE FROM news WHERE fetched_at < $1;

-- name: SearchNewsByTitle :many
SELECT * FROM news
WHERE title ILIKE '%' || $1 || '%'
ORDER BY published_at DESC NULLS LAST
LIMIT $2 OFFSET $3;

-- name: GetLatestNewsBySource :one
SELECT * FROM news
WHERE source = $1
ORDER BY published_at DESC NULLS LAST
LIMIT 1;

