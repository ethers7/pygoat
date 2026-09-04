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

# Run as an unprivileged user; the Flask reloader writes __pycache__ under
# /app, so hand that tree to the non-root user.
RUN useradd --create-home --uid 1000 --shell /bin/bash pygoat \
    && chown -R pygoat:pygoat /app

# Expose port 5000
EXPOSE 5000

USER pygoat

# Run the application
CMD ["python", "app.py"]
