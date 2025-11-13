-- Migration: Fix service path unique constraint to allow reusing paths from disabled services
-- Date: 2025-11-13
-- Issue: Users cannot create services with paths that were previously used by disabled/deleted services
-- Solution: Change from global unique constraint to partial unique index (only for enabled services)

-- Drop the old unique constraint that applies to all rows
ALTER TABLE services DROP CONSTRAINT IF EXISTS services_path_key;

-- Create a partial unique index that only enforces uniqueness for enabled services
-- This allows disabled services to have duplicate paths, enabling path reuse after deletion
CREATE UNIQUE INDEX IF NOT EXISTS services_path_enabled_unique
ON services(path)
WHERE enabled = true;

-- Result: Paths can now be reused when the original service is disabled/deleted
-- Active services still maintain unique paths to prevent conflicts
