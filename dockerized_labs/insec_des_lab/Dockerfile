FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=main.py
# Used by `flask run` below and by main.py's app.run(), which otherwise binds
# loopback only and would not be reachable through the published port.
ENV FLASK_RUN_HOST=0.0.0.0

# Run the lab as an unprivileged user instead of root.
# uid/gid 1000 matches the usual host user so the bind-mounted /app
# (see docker-compose.yml) stays writable for the Flask reloader cache.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app

EXPOSE 8080

USER appuser

CMD ["flask", "run", "--debug", "--port=8080"]
