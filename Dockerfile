FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    EASYSHARK_STATE_DIR=/data/.easyshark \
    EASYSHARK_PROCESS_SANDBOX=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 10001 easyshark && \
    mkdir -p /data /home/easyshark/.easyshark && \
    chown -R easyshark:easyshark /app /data /home/easyshark
USER easyshark
VOLUME ["/data"]
EXPOSE 8765
ENTRYPOINT ["python", "main.py"]
