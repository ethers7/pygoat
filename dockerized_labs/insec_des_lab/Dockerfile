FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0

# Create an unprivileged user and give it ownership of the app directory so the
# application can still write to /app without being root
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home --shell /bin/sh appuser \
    && chown -R appuser:appuser /app

EXPOSE 8080

# Drop root privileges before running the application
USER appuser

CMD ["flask", "run", "--debug", "--port=8080"]
