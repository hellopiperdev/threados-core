#!/bin/bash

# ThreadOS Codespace Setup Script
# Runs once, automatically, when a Codespace is first created.
# Installs PostgreSQL 15, creates the development database, and verifies everything works.

set -e  # Exit immediately if any command fails

echo ""
echo "=================================================="
echo "  ThreadOS Codespace Setup"
echo "=================================================="
echo ""

# ----------------------------------------------------------------
# Enable passwordless sudo for this setup (Codespace container is ephemeral)
# ----------------------------------------------------------------
echo "→ Configuring sudo for automated setup..."
echo "node ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/node-nopasswd > /dev/null
sudo chmod 0440 /etc/sudoers.d/node-nopasswd
echo "  ✓ Sudo configured"

# ----------------------------------------------------------------
# Install PostgreSQL 15
# ----------------------------------------------------------------
echo "→ Installing PostgreSQL 15..."

# Add the official PostgreSQL apt repository (needed for version 15 on Bullseye)
sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt bullseye-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add - > /dev/null 2>&1

sudo apt-get update -qq
sudo apt-get install -y -qq postgresql-15 postgresql-client-15 > /dev/null

echo "  ✓ PostgreSQL 15 installed"

# ----------------------------------------------------------------
# Start PostgreSQL
# ----------------------------------------------------------------
echo "→ Starting PostgreSQL service..."
sudo service postgresql start
echo "  ✓ PostgreSQL service running"

# ----------------------------------------------------------------
# Create the database and set the postgres user password
# ----------------------------------------------------------------
echo "→ Creating threados_dev database..."

sudo -u postgres psql <<EOF > /dev/null
CREATE DATABASE threados_dev;
ALTER USER postgres WITH PASSWORD 'postgres';
EOF

echo "  ✓ Database 'threados_dev' created"
echo "  ✓ User 'postgres' password set"

# ----------------------------------------------------------------
# Configure PostgreSQL to accept password authentication on localhost
# ----------------------------------------------------------------
echo "→ Configuring PostgreSQL authentication..."

PG_HBA=$(sudo -u postgres psql -t -P format=unaligned -c "SHOW hba_file;")
sudo sed -i 's/^local\s*all\s*postgres\s*peer/local all postgres md5/' "$PG_HBA"
sudo service postgresql restart

echo "  ✓ Authentication configured"

# ----------------------------------------------------------------
# Verify the connection works
# ----------------------------------------------------------------
echo "→ Verifying database connection..."

PGPASSWORD=postgres psql -h localhost -U postgres -d threados_dev -c "SELECT version();" > /dev/null

echo "  ✓ Connection verified"

# ----------------------------------------------------------------
# Done
# ----------------------------------------------------------------
echo ""
echo "=================================================="
echo "  ✓ ThreadOS Codespace Ready!"
echo "=================================================="
echo ""
echo "  Database:  threados_dev"
echo "  Host:      localhost"
echo "  Port:      5432"
echo "  User:      postgres"
echo "  Password:  postgres  (development only)"
echo ""
echo "  To connect from the terminal:"
echo "    psql -h localhost -U postgres -d threados_dev"
echo "    (password: postgres)"
echo ""
echo "=================================================="
echo ""
