// config/config.go

package config

import (
	"crypto/tls"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	redigo "github.com/gomodule/redigo/redis"
	"github.com/joho/godotenv"
)

// Config holds all configuration for the application.
type Config struct {
	Server        ServerConfig
	Database      DatabaseConfig
	Redis         RedisConfig
	OIDC          OIDCConfig
	CORS          CORSConfig
	SessionSecret string
}

// DatabaseConfig holds database connection configuration.
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

// GetDSN returns the PostgreSQL connection string (lib/pq format).
func (d *DatabaseConfig) GetDSN() string {
	return "host=" + d.Host +
		" port=" + d.Port +
		" user=" + d.User +
		" password=" + d.Password +
		" dbname=" + d.Name +
		" sslmode=" + d.SSLMode
}

// GetConnString returns the PostgreSQL connection string (pgx format).
func (d *DatabaseConfig) GetConnString() string {
	return "postgres://" + d.User + ":" + d.Password +
		"@" + d.Host + ":" + d.Port +
		"/" + d.Name + "?sslmode=" + d.SSLMode
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Host                  string
	Port                  string
	Username              string
	Password              string
	DB                    int
	TLSEnabled            bool
	TLSInsecureSkipVerify bool
}

// GetAddr returns the Redis address in host:port format.
func (r *RedisConfig) GetAddr() string {
	return r.Host + ":" + r.Port
}

// GetTLSConfig returns a TLS configuration when TLS is enabled, otherwise nil.
func (r *RedisConfig) GetTLSConfig() *tls.Config {
	if !r.TLSEnabled {
		return nil
	}

	return &tls.Config{
		InsecureSkipVerify: r.TLSInsecureSkipVerify,
	}
}

// NewRedisPool creates a redigo connection pool with TLS support if enabled.
func (r *RedisConfig) NewRedisPool() *redigo.Pool {
	return &redigo.Pool{
		MaxIdle:     10,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redigo.Conn, error) {
			opts := []redigo.DialOption{
				redigo.DialPassword(r.Password),
			}

			if r.TLSEnabled {
				opts = append(opts,
					redigo.DialTLSConfig(r.GetTLSConfig()),
					redigo.DialUseTLS(true),
				)
			}

			return redigo.Dial("tcp", r.GetAddr(), opts...)
		},
		TestOnBorrow: func(c redigo.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			_, err := c.Do("PING")
			return err
		},
	}
}

// ServerConfig holds server-related configuration.
type ServerConfig struct {
	Host string
	Port string
}

// OIDCConfig holds OpenID Connect configuration.
type OIDCConfig struct {
	Issuer                string
	ClientID              string
	ClientSecret          string
	RedirectURL           string
	Scopes                []string
	EndSessionURL         string
	PostLogoutRedirectURL string
}

// CORSConfig holds CORS-related configuration.
type CORSConfig struct {
	AllowOrigins     []string
	AllowAllOrigins  bool
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           int
}

// Load reads configuration from environment variables.
// .env file is optional (useful for local development, not needed in Docker)
func Load() (*Config, error) {
	// Try to load .env file, but don't fail if it doesn't exist
	// This allows the app to work in Docker where env vars are set directly
	// Try multiple common locations for .env file
	envPaths := []string{".env", "../.env", "../../.env"}
	for _, path := range envPaths {
		if err := godotenv.Load(path); err == nil {
			log.Printf("Loaded .env file from: %s", path)
			break
		}
	}

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		// Generate a warning but don't fail - useful for development
		log.Printf("WARNING: SESSION_SECRET not set, using default (INSECURE for production)")
		sessionSecret = "default-insecure-secret-change-in-production"
	}

	oidcIssuer := os.Getenv("OIDC_ISSUER")
	oidcClientID := os.Getenv("OIDC_CLIENT_ID")
	oidcClientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	oidcRedirectURL := os.Getenv("OIDC_REDIRECT_URL")
	oidcScopes := strings.TrimSpace(os.Getenv("OIDC_SCOPES"))
	if oidcScopes == "" {
		oidcScopes = "openid,profile,email"
	}
	rawScopes := strings.Split(oidcScopes, ",")
	for i := range rawScopes {
		rawScopes[i] = strings.TrimSpace(rawScopes[i])
	}
	endSessionURL := strings.TrimSpace(os.Getenv("OIDC_END_SESSION_URL"))
	postLogoutRedirect := strings.TrimSpace(os.Getenv("OIDC_POST_LOGOUT_REDIRECT_URL"))

	// CORS configuration
	corsConfig := loadCORSConfig()

	// Database configuration
	dbConfig := DatabaseConfig{
		Host:     getEnv("POSTGRES_HOST", "localhost"),
		Port:     getEnv("POSTGRES_PORT", "5432"),
		User:     getEnv("POSTGRES_USER", "pguser"),
		Password: getEnv("POSTGRES_PASSWORD", "pgpassword"),
		Name:     getEnv("POSTGRES_DB", "pgdb"),
		SSLMode:  getEnv("POSTGRES_SSLMODE", "disable"),
	}

	// Redis configuration
	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))
	redisTLSEnabled := strings.EqualFold(getEnv("REDIS_TLS_ENABLED", "false"), "true")
	redisTLSInsecureSkipVerify := strings.EqualFold(getEnv("REDIS_TLS_INSECURE_SKIP_VERIFY", "false"), "true")
	redisConfig := RedisConfig{
		Host:                  getEnv("REDIS_HOST", "localhost"),
		Port:                  getEnv("REDIS_PORT", "6379"),
		Username:              getEnv("REDIS_USERNAME", ""),
		Password:              getEnv("REDIS_PASSWORD", ""),
		DB:                    redisDB,
		TLSEnabled:            redisTLSEnabled,
		TLSInsecureSkipVerify: redisTLSInsecureSkipVerify,
	}

	return &Config{
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "0.0.0.0"), // 0.0.0.0 allows access from outside container
			Port: getEnv("SERVER_PORT", "3000"),
		},
		Database: dbConfig,
		Redis:    redisConfig,
		OIDC: OIDCConfig{
			Issuer:                oidcIssuer,
			ClientID:              oidcClientID,
			ClientSecret:          oidcClientSecret,
			RedirectURL:           oidcRedirectURL,
			Scopes:                rawScopes,
			EndSessionURL:         endSessionURL,
			PostLogoutRedirectURL: postLogoutRedirect,
		},
		CORS:          corsConfig,
		SessionSecret: sessionSecret,
	}, nil
}

// loadCORSConfig loads CORS configuration from environment variables.
func loadCORSConfig() CORSConfig {
	// Allow all origins by default (can be restricted via CORS_ALLOW_ORIGINS)
	allowAllOrigins := getEnv("CORS_ALLOW_ALL_ORIGINS", "true") == "true"

	var allowOrigins []string
	if !allowAllOrigins {
		originsStr := getEnv("CORS_ALLOW_ORIGINS", "")
		if originsStr != "" {
			allowOrigins = strings.Split(originsStr, ",")
			// Trim whitespace
			for i := range allowOrigins {
				allowOrigins[i] = strings.TrimSpace(allowOrigins[i])
			}
		}
	}

	// Allow methods
	methodsStr := getEnv("CORS_ALLOW_METHODS", "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS")
	allowMethods := strings.Split(methodsStr, ",")
	for i := range allowMethods {
		allowMethods[i] = strings.TrimSpace(allowMethods[i])
	}

	// Allow headers
	headersStr := getEnv("CORS_ALLOW_HEADERS", "Origin,Content-Type,Accept,Authorization")
	allowHeaders := strings.Split(headersStr, ",")
	for i := range allowHeaders {
		allowHeaders[i] = strings.TrimSpace(allowHeaders[i])
	}

	// Expose headers
	exposeStr := getEnv("CORS_EXPOSE_HEADERS", "Content-Length")
	exposeHeaders := strings.Split(exposeStr, ",")
	for i := range exposeHeaders {
		exposeHeaders[i] = strings.TrimSpace(exposeHeaders[i])
	}

	// Allow credentials
	allowCredentials := getEnv("CORS_ALLOW_CREDENTIALS", "true") == "true"

	// Max age (in seconds, default 12 hours)
	maxAgeStr := getEnv("CORS_MAX_AGE", "43200")
	maxAge, _ := strconv.Atoi(maxAgeStr)
	if maxAge <= 0 {
		maxAge = 43200 // 12 hours default
	}

	return CORSConfig{
		AllowOrigins:     allowOrigins,
		AllowAllOrigins:  allowAllOrigins,
		AllowMethods:     allowMethods,
		AllowHeaders:     allowHeaders,
		ExposeHeaders:    exposeHeaders,
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}
}

// GetCORSConfig returns the gin-contrib/cors Config based on the CORSConfig.
func (c *CORSConfig) GetCORSConfig() cors.Config {
	config := cors.Config{
		AllowMethods:     c.AllowMethods,
		AllowHeaders:     c.AllowHeaders,
		ExposeHeaders:    c.ExposeHeaders,
		AllowCredentials: c.AllowCredentials,
		MaxAge:           time.Duration(c.MaxAge) * time.Second,
	}

	if c.AllowAllOrigins {
		config.AllowOriginFunc = func(origin string) bool {
			return true
		}
	} else if len(c.AllowOrigins) > 0 {
		config.AllowOrigins = c.AllowOrigins
	} else {
		// Default: allow all if nothing specified
		config.AllowOriginFunc = func(origin string) bool {
			return true
		}
	}

	return config
}

// getEnv returns the value of an environment variable or a default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
