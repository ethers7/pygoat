FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0
# main.py defaults to loopback when run directly; a container must bind a
# container-visible address for the published port (see docker-compose.yml)
# to be reachable.
ENV INSEC_DES_LAB_HOST=0.0.0.0

# Run the app as an unprivileged user instead of root.
# UID/GID 1000 matches the usual host user so the bind-mounted project
# directory (see docker-compose.yml) stays readable/writable in-container.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app

# Port 8080 is non-privileged, so it can be bound without root
EXPOSE 8080

USER appuser

CMD ["flask", "run", "--debug", "--port=8080"]
