FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0
# main.py binds to loopback by default so a direct "python main.py" run on a
# workstation is not reachable from the LAN. In a container the network
# namespace is the isolation boundary and the published port (-p 8080:8080)
# must reach the app, so bind every interface here explicitly.
ENV INSEC_DES_LAB_HOST=0.0.0.0

# Run as an unprivileged user; the Flask reloader writes __pycache__ under
# /app, so hand that tree to the non-root user.
RUN useradd --create-home --uid 1000 --shell /bin/bash pygoat \
    && chown -R pygoat:pygoat /app

EXPOSE 8080

USER pygoat

CMD ["flask", "run", "--debug", "--port=8080"]
