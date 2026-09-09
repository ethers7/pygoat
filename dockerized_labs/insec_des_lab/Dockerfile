FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0

# Create an unprivileged user and give it ownership of the app directory
# (Flask needs to write to /app, e.g. the reloader cache and static files)
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app

# 8080 is unprivileged, so it can be bound without root
EXPOSE 8080

# Do not run the app as root
USER appuser

CMD ["flask", "run", "--debug", "--port=8080"]
