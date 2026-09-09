FROM python:3.11.0b1-buster


# set work directory
WORKDIR /app


# dependencies for psycopg2
RUN apt-get update && apt-get install --no-install-recommends -y dnsutils=1:9.11.5.P4+dfsg-5.1+deb10u11 libpq-dev=11.16-0+deb10u1 python3-dev=3.7.3-1 && apt-get clean && rm -rf /var/lib/apt/lists/*


# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1


# Install dependencies
RUN python -m pip install --no-cache-dir pip==22.0.4
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt


# copy project
COPY . /app/


# Run the app as an unprivileged user instead of root.
# uid/gid 1000 matches the usual host user so the bind-mounted /app
# (see docker-compose.yml) stays writable for db.sqlite3 and staticfiles.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh appuser


# install pygoat
EXPOSE 8000


# Migrate during the build, then hand /app to appuser: the sqlite database
# and its journal files are created next to db.sqlite3 at runtime.
RUN python3 /app/manage.py migrate && chown -R appuser:appuser /app
WORKDIR /app
USER appuser
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers","6", "pygoat.wsgi"]
