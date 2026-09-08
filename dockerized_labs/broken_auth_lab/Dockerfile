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

# Create an unprivileged user and give it ownership of the app directory so the
# application can still write to /app without being root
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app

# Expose port 5000
EXPOSE 5000

# Drop root privileges before running the application
USER appuser

# Run the application
CMD ["python", "app.py"]