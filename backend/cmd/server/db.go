package main

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/redis/go-redis/v9"

	"hkers-backend/config"
)

// initDB creates and verifies a pgx pool based on configuration.
func initDB(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	log.Printf("Connecting to database at %s:%s", cfg.Database.Host, cfg.Database.Port)

	pool, err := pgxpool.New(ctx, cfg.Database.GetConnString())
	if err != nil {
		return nil, err
	}

	// Verify connectivity early
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	log.Printf("Database connection established successfully")
	return pool, nil
}

// initRedis creates a Redis client and verifies connectivity with a PING.
func initRedis(ctx context.Context, cfg *config.Config) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:     cfg.Redis.GetAddr(),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	log.Printf("Connecting to Redis at %s", opts.Addr)
	client := redis.NewClient(opts)

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, err
	}

	log.Printf("Redis connection established successfully")
	return client, nil
}
