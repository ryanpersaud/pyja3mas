FROM python:3.7-slim-buster

RUN addgroup --gid 1000 --system appgroup && \
    adduser --uid 1000 --system --gid 1000 appuser

WORKDIR /home/appuser

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY https_server.py dynamodb_access.py ja3.py log_conf.py ./

USER appuser

EXPOSE 4443/tcp

ENTRYPOINT ["python3", "https_server.py"]
