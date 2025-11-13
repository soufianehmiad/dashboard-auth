-- Update admin user role to super_admin
-- This should be run once to promote the existing admin user
-- Run with: docker exec -i dashboard-postgres psql -U dashboard_app -d dashboard < database/update-admin-role.sql

UPDATE users
SET role = 'super_admin'
WHERE username = 'admin'
  AND role != 'super_admin';

-- Verify the update
SELECT id, username, role, created_at
FROM users
WHERE username = 'admin';
