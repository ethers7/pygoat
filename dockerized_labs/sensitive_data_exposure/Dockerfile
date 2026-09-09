FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Add script to make sure migrations run properly
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run the lab as an unprivileged user instead of root.
# uid/gid 1000 matches the usual host user so the bind-mounted /app
# (see docker-compose.yml) stays writable for db.sqlite3 and migrations.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app /entrypoint.sh

EXPOSE 8000

USER appuser

# Use the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
