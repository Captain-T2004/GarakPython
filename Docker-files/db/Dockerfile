# Dockerfile for PostgreSQL with custom user setup
FROM postgres:latest

# Set environment variables for initial database and user creation
ENV POSTGRES_DB=scannerdb
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=admin_password

# Copy initialization script
COPY init-user.sh /docker-entrypoint-initdb.d/init-user.sh
RUN chmod +x /docker-entrypoint-initdb.d/init-user.sh

# Expose the standard PostgreSQL port
EXPOSE 5432
