#!/bin/bash
set -e

# Create the new user with a password
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER garak_user WITH PASSWORD 'garak_password';
    GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO garak_user;
EOSQL
