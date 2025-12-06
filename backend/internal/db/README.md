# Database Layer (`internal/db`)

This directory contains the database schema, SQL queries, and sqlc configuration for generating type-safe Go code.

## Directory Structure

```
internal/db/
├── README.md           # This file
├── sqlc.yaml           # sqlc configuration
├── schema/             # Database schema files
│   ├── schema.sql      # Main schema (tables, triggers, indexes)
│   └── seed.sql        # Initial seed data (roles, permissions)
├── queries/            # SQL query files
│   ├── user.sql        # User-related queries
│   ├── role.sql        # Role & permission queries
│   ├── station.sql     # Supply station queries
│   ├── donation.sql    # Donation queries
│   ├── checkin.sql     # Check-in queries
│   ├── news.sql        # News queries
│   └── audit.sql       # RBAC audit log queries
└── generated/          # Auto-generated Go code (do not edit!)
```

## Prerequisites

### Install sqlc

**Windows (using Go):**
```powershell
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

**macOS (using Homebrew):**
```bash
brew install sqlc
```

**Linux (using Go):**
```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

**Docker:**
```bash
docker pull sqlc/sqlc
```

### Verify Installation
```bash
sqlc version
```

## Generating Go Code

### Using the provided scripts (Recommended)

**Windows (PowerShell):**
```powershell
# From project root
.\scripts\generate-sqlc.ps1
```

**Linux/macOS (Bash):**
```bash
# From project root
./scripts/generate-sqlc.sh
```

### Using sqlc directly

Navigate to the `internal/db` directory and run:

```powershell
# From project root
cd internal/db
sqlc generate
```

Or from the project root:

```powershell
# From project root
sqlc generate -f internal/db/sqlc.yaml
```

### Using Docker (standalone)

```powershell
# From project root
docker run --rm -v "${PWD}:/src" -w /src/internal/db sqlc/sqlc generate
```

### Before Docker Build

**Important:** You must generate sqlc code manually before building the Docker image:

```powershell
# Generate sqlc code first
cd internal/db
sqlc generate

# Then build Docker image
cd ../..
docker compose -f deploy/docker-compose.yml build
```

The Dockerfile expects the generated code to already exist in `internal/db/generated/`.

### Expected Output

After running `sqlc generate`, you should see new files in `internal/db/generated/`:

```
generated/
├── db.go           # Database connection interface
├── models.go       # Generated Go structs for tables
├── querier.go      # Interface for all queries
├── user.sql.go     # Generated code for user queries
├── role.sql.go     # Generated code for role queries
├── station.sql.go  # Generated code for station queries
├── donation.sql.go # Generated code for donation queries
├── checkin.sql.go  # Generated code for checkin queries
├── news.sql.go     # Generated code for news queries
└── audit.sql.go    # Generated code for audit queries
```

## Database Setup

### 1. Create PostgreSQL Database

```sql
CREATE DATABASE hkers;
```

### 2. Enable PostGIS Extension

The schema uses PostGIS for geospatial queries. Enable it:

```sql
\c hkers
CREATE EXTENSION postgis;
```

### 3. Run Schema Migration

```powershell
# Using psql
psql -d hkers -f internal/db/schema/schema.sql
```

### 4. Seed Initial Data

```powershell
# Using psql
psql -d hkers -f internal/db/schema/seed.sql
```

## Usage in Go Code

### Basic Setup

```go
package main

import (
    "context"
    "log"
    
    "github.com/jackc/pgx/v5/pgxpool"
    db "your-project/internal/db/generated"
)

func main() {
    ctx := context.Background()
    
    // Connect to database
    pool, err := pgxpool.New(ctx, "postgres://user:pass@localhost:5432/hkers")
    if err != nil {
        log.Fatal(err)
    }
    defer pool.Close()
    
    // Create queries instance
    queries := db.New(pool)
    
    // Use generated queries
    user, err := queries.GetUserByUsername(ctx, "admin")
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("User: %+v", user)
}
```

### Example: Create User with Role

```go
func CreateUserWithRole(ctx context.Context, q *db.Queries, username, email string) error {
    // Create user (password_hash would be set by your application logic)
    user, err := q.CreateUser(ctx, db.CreateUserParams{
        Username:     username,
        PasswordHash: "", // Set by your application's password hashing logic
        Email:        &email,
        TrustPoints:  0,
    })
    if err != nil {
        return err
    }
    
    // Get the 'user' role
    role, err := q.GetRoleByName(ctx, "user")
    if err != nil {
        return err
    }
    
    // Assign role to user
    _, err = q.AssignRoleToUser(ctx, db.AssignRoleToUserParams{
        UserID: user.ID,
        RoleID: role.ID,
    })
    
    return err
}
```

### Example: Check User Permission

```go
func HasPermission(ctx context.Context, q *db.Queries, userID int32, permission string) (bool, error) {
    result, err := q.CheckUserPermission(ctx, db.CheckUserPermissionParams{
        ID:   userID,
        Name: permission,
    })
    if err != nil {
        return false, err
    }
    return result.HasPermission, nil
}
```

## Modifying the Schema

1. **Edit schema files** in `schema/`
2. **Update queries** in `queries/` as needed
3. **Regenerate code**: `sqlc generate`
4. **Apply migrations** to your database

### Adding New Queries

1. Add your SQL query to the appropriate file in `queries/`
2. Use sqlc comment annotations:
   - `:one` - Returns a single row
   - `:many` - Returns multiple rows
   - `:exec` - Executes without returning data
   - `:execrows` - Returns affected row count

Example:
```sql
-- name: GetActiveUsers :many
SELECT * FROM users
WHERE trust_points > 0
ORDER BY trust_points DESC
LIMIT $1;
```

3. Run `sqlc generate`

## Validation

Check your SQL syntax before generating:

```powershell
sqlc compile -f internal/db/sqlc.yaml
```

## Troubleshooting

### "relation does not exist"
- Ensure the schema has been applied to the database
- Check that PostGIS extension is enabled

### "type does not exist" (for enums)
- Run the schema.sql which creates the `app_role` and `app_permission` enum types

### sqlc compilation errors
- Verify SQL syntax matches PostgreSQL standards
- Check that all referenced tables exist in schema.sql
- Ensure column names match exactly

## Notes for Production

1. **Integrate with app-level enforcement** - Query `user_roles` → `role_permissions` in Go middleware
2. **Consider Row-Level Security (RLS)** for data tables
3. **Use caching** (e.g., Redis) for permission checks to avoid DB hits
4. **Set session variables** for auditing/RLS: `SET app.current_user_id = 123;`

