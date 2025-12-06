-- seed.sql
-- Seed data: Insert initial roles and permissions (run separately or as migration)
-- Note: Adjust assignments based on fine-grained permissions

INSERT INTO roles (name, description) VALUES
    ('admin', 'Full system access, including user management and data oversight'),
    ('manager', 'Manage supply stations, donations, and moderate content'),
    ('user', 'General users: register stations, donate, check-in, view data');

INSERT INTO permissions (name, description) VALUES
    ('create_users', 'Create new users'),
    ('read_users', 'View/list user details'),
    ('update_users', 'Update user information'),
    ('delete_users', 'Delete users'),
    ('assign_roles', 'Assign or change user roles'),
    ('create_stations', 'Register new supply stations'),
    ('read_stations', 'View/list supply stations'),
    ('update_stations', 'Update station details'),
    ('delete_stations', 'Delete supply stations'),
    ('create_checkins', 'Perform check-ins at stations'),
    ('read_checkins', 'View check-in logs'),
    ('verify_stations', 'Manually verify stations'),
    ('create_donations', 'Register new donations'),
    ('read_donations', 'View/list donations'),
    ('update_donations', 'Update donation status'),
    ('delete_donations', 'Delete donations'),
    ('read_news', 'View and fetch news items'),
    ('create_news', 'Add new news items'),
    ('update_news', 'Update existing news items'),
    ('delete_news', 'Delete news items'),
    ('create_supply_needs', 'Add supply needs to stations'),
    ('read_supply_needs', 'View supply needs'),
    ('update_supply_needs', 'Update supply needs'),
    ('delete_supply_needs', 'Delete supply needs');

-- Example assignments: Assign permissions to roles
-- For admin: all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p WHERE r.name = 'admin';

-- For manager: selected fine-grained permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN (
    'create_stations', 'read_stations', 'update_stations', 'delete_stations',
    'create_checkins', 'read_checkins', 'verify_stations',
    'create_donations', 'read_donations', 'update_donations', 'delete_donations',
    'create_news', 'read_news', 'update_news', 'delete_news',
    'create_supply_needs', 'read_supply_needs', 'update_supply_needs', 'delete_supply_needs'
) WHERE r.name = 'manager';

-- For user: basic permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN (
    'create_stations', 'read_stations',
    'create_checkins', 'read_checkins',
    'create_donations', 'read_donations',
    'read_news',
    'create_supply_needs', 'read_supply_needs'
) WHERE r.name = 'user';

