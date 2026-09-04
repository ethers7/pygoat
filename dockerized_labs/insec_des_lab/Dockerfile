FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0

# Run as an unprivileged user; the Flask reloader writes __pycache__ under
# /app, so hand that tree to the non-root user.
RUN useradd --create-home --uid 1000 --shell /bin/bash pygoat \
    && chown -R pygoat:pygoat /app

EXPOSE 8080

USER pygoat

CMD ["flask", "run", "--debug", "--port=8080"]
