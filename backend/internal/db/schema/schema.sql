-- schema.sql
-- This file defines the database schema for sqlc to generate type-safe Go code from queries.

-- Assuming PostGIS is enabled: CREATE EXTENSION postgis;

-- Custom types for roles and permissions (using enums for type safety and to prevent invalid values)
-- Enums make the schema more robust by enforcing valid roles/permissions at the database level.
-- If new roles/permissions are needed, use ALTER TYPE to add them.

CREATE TYPE app_role AS ENUM ('admin', 'manager', 'user');

CREATE TYPE app_permission AS ENUM (
    -- User management (split for granularity)
    'create_users',       -- Create new users
    'read_users',         -- View/list user details (consider 'read_own_users' if ownership-based)
    'update_users',       -- Update user information (e.g., email, trust_points)
    'delete_users',       -- Delete users
    'assign_roles',       -- Assign or change user roles

    -- Supply stations management
    'create_stations',    -- Register new supply stations
    'read_stations',      -- View/list supply stations
    'update_stations',    -- Update station details (e.g., location, verification_threshold)
    'delete_stations',    -- Delete supply stations

    -- Station verification and check-ins
    'create_checkins',    -- Perform check-ins at stations
    'read_checkins',      -- View check-in logs
    'verify_stations',    -- Manually verify stations (if applicable beyond automatic triggers)

    -- Donations management
    'create_donations',   -- Register new donations
    'read_donations',     -- View/list donations
    'update_donations',   -- Update donation status (e.g., track delivery)
    'delete_donations',   -- Delete donations

    -- News management
    'read_news',          -- View and fetch news items (renamed from view_news for consistency)
    'create_news',        -- Add new news items
    'update_news',        -- Update existing news items
    'delete_news',        -- Delete news items

    -- Additional fine-grained permissions (expand as needed for other entities like supply_needs)
    'create_supply_needs',-- Add supply needs to stations
    'read_supply_needs',  -- View supply needs
    'update_supply_needs',-- Update supply needs (e.g., quantity, urgency)
    'delete_supply_needs' -- Delete supply needs
);

-- Roles table: Defines user roles for RBAC.
-- Includes timestamps for auditing and tracking changes.
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name app_role UNIQUE NOT NULL,
    description TEXT,  -- Optional details about the role
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Permissions table: Defines individual permissions that can be assigned to roles.
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name app_permission UNIQUE NOT NULL,
    description TEXT,  -- Optional details about what the permission allows
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Role_Permissions junction table: Assigns permissions to roles (many-to-many relationship).
-- This allows managing permissions for each role by inserting/deleting records here.
CREATE TABLE role_permissions (
    id SERIAL PRIMARY KEY,  -- Optional surrogate key for easier querying/logging
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE NOT NULL,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (role_id, permission_id)  -- Prevent duplicate assignments
);

-- Users table: Stores user information, including volunteers and registrants.
-- Trust points are used to adjust verification thresholds for supply stations they register.
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    oidc_sub VARCHAR(255) UNIQUE NOT NULL,  -- OIDC subject identifier (sub claim from ID token)
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    is_active BOOLEAN DEFAULT FALSE,  -- Must be TRUE for user to access the app
    trust_points INTEGER DEFAULT 0,  -- Increases when their registered stations are verified
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- User_Roles junction table: Assigns roles to users (many-to-many for flexibility).
-- This supports users having multiple roles, which is more production-ready than a single role_id per user.
CREATE TABLE user_roles (
    id SERIAL PRIMARY KEY,  -- Optional surrogate key
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, role_id)  -- Prevent duplicate role assignments per user
);

-- Supply_Stations table: Represents supply locations with location data, verification status, and needs summary.
-- Location uses PostGIS POINT for geospatial queries (requires PostGIS extension).
CREATE TABLE supply_stations (
    id SERIAL PRIMARY KEY,
    registered_by INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- User who registered the station
    location GEOGRAPHY(POINT, 4326) NOT NULL,  -- Lat/Long for mapping (SRID 4326 for WGS84)
    verification_count INTEGER DEFAULT 0,  -- Increments with check-ins
    verification_threshold INTEGER NOT NULL,  -- Set at creation based on registrant's trust_points (e.g., 5 - trust_points, min 1)
    is_verified BOOLEAN DEFAULT FALSE,  -- Updated when verification_count >= verification_threshold
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Supply_Needs table: Details what supplies are needed at each station.
-- Using a separate table for multiple needs per station.
CREATE TABLE supply_needs (
    id SERIAL PRIMARY KEY,
    station_id INTEGER REFERENCES supply_stations(id) ON DELETE CASCADE,
    supply_type VARCHAR(255) NOT NULL,  -- e.g., 'water', 'food', 'medical'
    quantity_needed INTEGER,  -- Optional, could be approximate
    description TEXT,  -- Additional details
    urgency_level VARCHAR(50),  -- e.g., 'high', 'medium', 'low'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(station_id, supply_type)  -- Prevent duplicates for the same type per station
);

-- Donations table: Registers supplies being delivered, with a code for volunteers to verify/track.
CREATE TABLE donations (
    id SERIAL PRIMARY KEY,
    donor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- Can be anonymous (NULL)
    station_id INTEGER REFERENCES supply_stations(id) ON DELETE CASCADE,
    supplies JSONB NOT NULL,  -- Flexible: e.g., {"water": 100, "food": 50} or array of items
    delivery_code VARCHAR(50) UNIQUE NOT NULL,  -- Unique code for volunteers to reference
    status VARCHAR(50) DEFAULT 'pending',  -- e.g., 'pending', 'in_transit', 'delivered'
    estimated_delivery TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Checkins table: Logs volunteer check-ins for verification.
-- Can include GPS to verify proximity (optional).
CREATE TABLE checkins (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,  -- Must be logged-in volunteer
    station_id INTEGER REFERENCES supply_stations(id) ON DELETE CASCADE,
    checkin_location GEOGRAPHY(POINT, 4326),  -- Optional: To verify on-scene (compare to station location)
    checkin_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,  -- Optional feedback
    UNIQUE(user_id, station_id)  -- Prevent multiple check-ins from same user
);

-- News table: Stores news from trusted sources for display/integration.
CREATE TABLE news (
    id SERIAL PRIMARY KEY,
    source VARCHAR(255) NOT NULL,  -- e.g., 'news.gov', 'trusted_media'
    title VARCHAR(255) NOT NULL,
    content TEXT,  -- Full text or summary
    url VARCHAR(512),  -- Link to original
    published_at TIMESTAMP WITH TIME ZONE,
    fetched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    relevant_to JSONB  -- Optional: Tags or station_ids it's related to
);

-- Trigger to update is_verified automatically
CREATE OR REPLACE FUNCTION update_verification_status()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    IF NEW.verification_count >= NEW.verification_threshold THEN
        NEW.is_verified = TRUE;
        -- Optionally, award trust points to registrant if newly verified
        IF OLD.is_verified = FALSE THEN
            UPDATE users
            SET trust_points = trust_points + 1  -- Or some point system
            WHERE id = NEW.registered_by;
        END IF;
    ELSE
        NEW.is_verified = FALSE;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_verification
BEFORE UPDATE ON supply_stations
FOR EACH ROW EXECUTE FUNCTION update_verification_status();

-- Trigger to increment verification_count on new check-in
CREATE OR REPLACE FUNCTION increment_verification_count()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE supply_stations
    SET verification_count = verification_count + 1
    WHERE id = NEW.station_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_increment_verification
AFTER INSERT ON checkins
FOR EACH ROW EXECUTE FUNCTION increment_verification_count();

-- Trigger function to automatically update 'updated_at' timestamps
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers to roles and permissions tables
CREATE TRIGGER trigger_update_roles
BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_update_permissions
BEFORE UPDATE ON permissions
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_update_supply_stations
BEFORE UPDATE ON supply_stations
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_update_supply_needs
BEFORE UPDATE ON supply_needs
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_update_donations
BEFORE UPDATE ON donations
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Optional: Audit log table for tracking changes to roles/permissions (production best practice)
CREATE TABLE rbac_audit_logs (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(50) NOT NULL,  -- e.g., 'role_permissions'
    action VARCHAR(10) NOT NULL,      -- e.g., 'INSERT', 'UPDATE', 'DELETE'
    old_data JSONB,                   -- Old row data (for updates/deletes)
    new_data JSONB,                   -- New row data (for inserts/updates)
    changed_by INTEGER REFERENCES users(id),  -- Who made the change (requires app to set)
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Example trigger for auditing role_permissions changes
-- Uses current_setting with missing_ok=true to handle cases where app.current_user_id isn't set (e.g., during seeding)
CREATE OR REPLACE FUNCTION audit_rbac_changes()
RETURNS TRIGGER AS $$
DECLARE
    current_user_id INTEGER;
BEGIN
    -- Get current user ID, returns NULL if not set (e.g., during migrations/seeding)
    BEGIN
        current_user_id := current_setting('app.current_user_id', true)::INTEGER;
    EXCEPTION WHEN OTHERS THEN
        current_user_id := NULL;
    END;

    IF (TG_OP = 'DELETE') THEN
        INSERT INTO rbac_audit_logs (table_name, action, old_data, changed_by)
        VALUES (TG_RELNAME, TG_OP, row_to_json(OLD), current_user_id);
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO rbac_audit_logs (table_name, action, old_data, new_data, changed_by)
        VALUES (TG_RELNAME, TG_OP, row_to_json(OLD), row_to_json(NEW), current_user_id);
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO rbac_audit_logs (table_name, action, new_data, changed_by)
        VALUES (TG_RELNAME, TG_OP, row_to_json(NEW), current_user_id);
    END IF;
    RETURN NULL;  -- For AFTER triggers
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_audit_role_permissions
AFTER INSERT OR UPDATE OR DELETE ON role_permissions
FOR EACH ROW EXECUTE FUNCTION audit_rbac_changes();

-- Indexes for performance
CREATE INDEX idx_supply_stations_location ON supply_stations USING GIST(location);
CREATE INDEX idx_checkins_station_id ON checkins(station_id);
CREATE INDEX idx_donations_station_id ON donations(station_id);
CREATE INDEX idx_supply_needs_station_id ON supply_needs(station_id);
CREATE INDEX idx_news_source ON news(source);
CREATE INDEX idx_users_trust_points ON users(trust_points);
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

