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

# Create an unprivileged user and give it ownership of the app directory
# (Flask needs to write to /app, e.g. the reloader cache and static files)
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app

# Expose port 5000 (unprivileged, so it can be bound without root)
EXPOSE 5000

# Do not run the app as root
USER appuser

# Run the application
CMD ["python", "app.py"] 