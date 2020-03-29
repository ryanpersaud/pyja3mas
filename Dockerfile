FROM python:3.8-slim-buster

# Create non-root user to run pyja3mas as
RUN useradd ja3user

WORKDIR /opt/pyja3mas

COPY requirements.txt *.py ./

RUN python3 -m pip install -r requirements.txt

RUN mkdir certs logs

# Generate key and certificate for pyja3mas
RUN openssl req -newkey rsa:4096 -nodes -keyout certs/privkey.pem -x509 -days 365 -out certs/fullchain.pem -subj "/C=US/ST=VA/L=Springfield/O=ACME/OU=IT/CN=localhost"

RUN chown -R ja3user:ja3user certs logs

WORKDIR /opt/pyja3mas

USER ja3user

CMD python3 https_server.py
