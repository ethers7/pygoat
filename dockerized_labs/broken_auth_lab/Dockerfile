FROM python:3.9-slim

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV PYTHONUNBUFFERED=1

# Run the app as an unprivileged user instead of root.
# UID/GID 1000 matches the usual host user so the bind-mounted project
# directory (see docker-compose.yml) stays readable/writable in-container.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app

# Expose port 5000 (non-privileged, usable without root)
EXPOSE 5000

USER appuser

# Run the application
CMD ["python", "app.py"]