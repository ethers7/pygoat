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

# CWE-489: `--debug` turned on the Werkzeug debugger in the shipped image, and
# that debugger hands out an interactive Python console on any unhandled
# exception, so the published port was remote code execution. Debug mode is now
# opt-in through the environment only: `flask run` reads FLASK_DEBUG itself, so
# FLASK_DEBUG=1 restores it for local debugging and it is off by default. The
# reloader is still asked for explicitly so the bind-mounted /app (see
# docker-compose.yml) keeps picking up edits, which does not expose a console.
CMD ["flask", "run", "--reload", "--port=8080"]
