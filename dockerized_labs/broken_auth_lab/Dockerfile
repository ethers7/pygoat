FROM python:3.9-slim

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set environment variables
ENV FLASK_APP=app.py
# Debug mode stays off: the Werkzeug debugger leaks source/config in tracebacks
# and offers an interactive console (arbitrary code execution).
ENV FLASK_DEBUG=0
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

# Serve through a production WSGI server instead of Flask's built-in
# development server, which is single threaded and not meant to face a network.
# gunicorn binds the same port 5000 as an unprivileged user and never enables
# the Werkzeug debugger.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"] 