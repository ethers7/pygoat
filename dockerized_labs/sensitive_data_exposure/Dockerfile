FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Add script to make sure migrations run properly
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

# Run the app as an unprivileged user instead of root.
# UID/GID 1000 matches the usual host user so the bind-mounted project
# directory (see docker-compose.yml) stays writable for makemigrations
# and the sqlite database file at /app/db.sqlite3.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app

EXPOSE 8000

USER appuser

# Use the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
