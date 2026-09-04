FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Add script to make sure migrations run properly
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run as an unprivileged user; the app writes db.sqlite3 and generated
# migrations under /app, so hand that tree to the non-root user.
RUN useradd --create-home --uid 1000 --shell /bin/bash pygoat \
    && chown -R pygoat:pygoat /app

EXPOSE 8000

USER pygoat

# Use the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
