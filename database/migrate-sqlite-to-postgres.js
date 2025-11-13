#!/usr/bin/env node

/**
 * SQLite to PostgreSQL Migration Script
 *
 * This script migrates data from the existing SQLite database to PostgreSQL
 *
 * Usage: node migrate-sqlite-to-postgres.js
 */

const sqlite3 = require('sqlite3').verbose();
const { Client } = require('pg');
const path = require('path');
require('dotenv').config();

// Configuration
const SQLITE_DB_PATH = path.join(__dirname, '..', 'data', 'users.db');
const PG_CONFIG = {
  host: process.env.POSTGRES_HOST || 'dashboard-postgres',
  port: process.env.POSTGRES_PORT || 5432,
  database: process.env.POSTGRES_DB || 'dashboard',
  user: process.env.POSTGRES_USER || 'dashboard_app',
  password: process.env.POSTGRES_PASSWORD
};

// Statistics
const stats = {
  users: { migrated: 0, errors: 0 },
  categories: { migrated: 0, errors: 0 },
  services: { migrated: 0, errors: 0 }
};

/**
 * Connect to SQLite database
 */
function connectSQLite() {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(SQLITE_DB_PATH, sqlite3.OPEN_READONLY, (err) => {
      if (err) {
        reject(err);
      } else {
        console.log('✓ Connected to SQLite database');
        resolve(db);
      }
    });
  });
}

/**
 * Connect to PostgreSQL database
 */
async function connectPostgreSQL() {
  const client = new Client(PG_CONFIG);
  await client.connect();
  console.log('✓ Connected to PostgreSQL database');
  return client;
}

/**
 * Query SQLite database
 */
function querySQLite(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
}

/**
 * Migrate users table
 */
async function migrateUsers(sqliteDb, pgClient) {
  console.log('\n📦 Migrating users...');

  const users = await querySQLite(sqliteDb, 'SELECT * FROM users');
  console.log(`   Found ${users.length} users in SQLite`);

  for (const user of users) {
    try {
      await pgClient.query(`
        INSERT INTO users (
          id, username, password, display_name,
          failed_login_attempts, locked_until, password_must_change,
          role, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (username) DO UPDATE SET
          password = EXCLUDED.password,
          display_name = EXCLUDED.display_name,
          failed_login_attempts = EXCLUDED.failed_login_attempts,
          locked_until = EXCLUDED.locked_until,
          password_must_change = EXCLUDED.password_must_change
      `, [
        user.id,
        user.username,
        user.password,
        user.display_name,
        user.failed_login_attempts || 0,
        user.locked_until,
        user.password_must_change || false,
        user.username === 'admin' ? 'super_admin' : 'user',  // Default role
        user.created_at || new Date().toISOString()
      ]);

      stats.users.migrated++;
      console.log(`   ✓ Migrated user: ${user.username}`);
    } catch (err) {
      stats.users.errors++;
      console.error(`   ✗ Error migrating user ${user.username}:`, err.message);
    }
  }

  // Update sequence
  if (users.length > 0) {
    const maxId = Math.max(...users.map(u => u.id));
    await pgClient.query(`SELECT setval('users_id_seq', $1, true)`, [maxId]);
  }
}

/**
 * Migrate categories table
 */
async function migrateCategories(sqliteDb, pgClient) {
  console.log('\n📦 Migrating categories...');

  const categories = await querySQLite(sqliteDb, 'SELECT * FROM categories');
  console.log(`   Found ${categories.length} categories in SQLite`);

  for (const category of categories) {
    try {
      await pgClient.query(`
        INSERT INTO categories (
          id, name, display_order, color, icon, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (id) DO UPDATE SET
          name = EXCLUDED.name,
          display_order = EXCLUDED.display_order,
          color = EXCLUDED.color,
          icon = EXCLUDED.icon
      `, [
        category.id,
        category.name,
        category.display_order || 0,
        category.color || '#58a6ff',
        category.icon || 'folder',
        category.created_at || new Date().toISOString()
      ]);

      stats.categories.migrated++;
      console.log(`   ✓ Migrated category: ${category.name}`);
    } catch (err) {
      stats.categories.errors++;
      console.error(`   ✗ Error migrating category ${category.name}:`, err.message);
    }
  }
}

/**
 * Migrate services table
 */
async function migrateServices(sqliteDb, pgClient) {
  console.log('\n📦 Migrating services...');

  const services = await querySQLite(sqliteDb, 'SELECT * FROM services');
  console.log(`   Found ${services.length} services in SQLite`);

  for (const service of services) {
    try {
      await pgClient.query(`
        INSERT INTO services (
          id, name, path, icon_url, category, service_type, proxy_target,
          api_url, api_key_env, display_order, enabled, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (path) DO UPDATE SET
          name = EXCLUDED.name,
          icon_url = EXCLUDED.icon_url,
          category = EXCLUDED.category,
          service_type = EXCLUDED.service_type,
          proxy_target = EXCLUDED.proxy_target,
          api_url = EXCLUDED.api_url,
          api_key_env = EXCLUDED.api_key_env,
          display_order = EXCLUDED.display_order,
          enabled = EXCLUDED.enabled
      `, [
        service.id,
        service.name,
        service.path,
        service.icon_url,
        service.category,
        service.service_type || 'external',
        service.proxy_target,
        service.api_url,
        service.api_key_env,
        service.display_order || 0,
        service.enabled !== 0,  // Convert SQLite 0/1 to boolean
        service.created_at || new Date().toISOString()
      ]);

      stats.services.migrated++;
      console.log(`   ✓ Migrated service: ${service.name}`);
    } catch (err) {
      stats.services.errors++;
      console.error(`   ✗ Error migrating service ${service.name}:`, err.message);
    }
  }

  // Update sequence
  if (services.length > 0) {
    const maxId = Math.max(...services.map(s => s.id));
    await pgClient.query(`SELECT setval('services_id_seq', $1, true)`, [maxId]);
  }
}

/**
 * Verify migration
 */
async function verifyMigration(pgClient) {
  console.log('\n🔍 Verifying migration...');

  const userCount = await pgClient.query('SELECT COUNT(*) as count FROM users');
  const categoryCount = await pgClient.query('SELECT COUNT(*) as count FROM categories');
  const serviceCount = await pgClient.query('SELECT COUNT(*) as count FROM services');

  console.log(`   Users in PostgreSQL: ${userCount.rows[0].count}`);
  console.log(`   Categories in PostgreSQL: ${categoryCount.rows[0].count}`);
  console.log(`   Services in PostgreSQL: ${serviceCount.rows[0].count}`);
}

/**
 * Print statistics
 */
function printStats() {
  console.log('\n' + '='.repeat(60));
  console.log('MIGRATION STATISTICS');
  console.log('='.repeat(60));
  console.log(`Users:      ${stats.users.migrated} migrated, ${stats.users.errors} errors`);
  console.log(`Categories: ${stats.categories.migrated} migrated, ${stats.categories.errors} errors`);
  console.log(`Services:   ${stats.services.migrated} migrated, ${stats.services.errors} errors`);
  console.log('='.repeat(60));

  const totalMigrated = stats.users.migrated + stats.categories.migrated + stats.services.migrated;
  const totalErrors = stats.users.errors + stats.categories.errors + stats.services.errors;

  console.log(`\nTOTAL: ${totalMigrated} records migrated, ${totalErrors} errors`);

  if (totalErrors === 0) {
    console.log('\n✅ Migration completed successfully!');
  } else {
    console.log('\n⚠️  Migration completed with errors. Please review the log above.');
  }
}

/**
 * Main migration function
 */
async function migrate() {
  console.log('🚀 Starting SQLite to PostgreSQL migration...\n');
  console.log('Configuration:');
  console.log(`   SQLite DB: ${SQLITE_DB_PATH}`);
  console.log(`   PostgreSQL: ${PG_CONFIG.user}@${PG_CONFIG.host}:${PG_CONFIG.port}/${PG_CONFIG.database}`);

  let sqliteDb, pgClient;

  try {
    // Connect to databases
    sqliteDb = await connectSQLite();
    pgClient = await connectPostgreSQL();

    // Run migrations
    await migrateUsers(sqliteDb, pgClient);
    await migrateCategories(sqliteDb, pgClient);
    await migrateServices(sqliteDb, pgClient);

    // Verify
    await verifyMigration(pgClient);

    // Print statistics
    printStats();

  } catch (err) {
    console.error('\n❌ Migration failed:', err);
    process.exit(1);
  } finally {
    // Close connections
    if (sqliteDb) {
      sqliteDb.close();
      console.log('\n✓ Closed SQLite connection');
    }
    if (pgClient) {
      await pgClient.end();
      console.log('✓ Closed PostgreSQL connection');
    }
  }
}

// Run migration
if (require.main === module) {
  migrate().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
}

module.exports = { migrate };
