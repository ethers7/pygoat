FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Add script to make sure migrations run properly
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create an unprivileged user and give it ownership of the app directory so the
# entrypoint can still run migrations and write db.sqlite3 without being root
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app \
    && chown appuser:appuser /entrypoint.sh

EXPOSE 8000

# Drop root privileges before running the application
USER appuser

# Use the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
