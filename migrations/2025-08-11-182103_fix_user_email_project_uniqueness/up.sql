-- Create the new composite unique index CONCURRENTLY first
-- This allows the same email across different projects but prevents duplicates within the same project
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_email_project_unique ON users (email, project_id) WHERE email IS NOT NULL;

-- Then drop the old unique index that enforces global email uniqueness
DROP INDEX IF EXISTS users_email_unique;

-- The existing index idx_users_email_project_id already provides optimization for queries,
-- but this new unique index ensures data integrity at the database level