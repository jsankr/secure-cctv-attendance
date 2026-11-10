FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg && rm -rf /var/lib/apt/lists/*
WORKDIR /srv/worker
COPY worker/requirements.txt .
# Swap onnxruntime for onnxruntime-openvino on Intel CPUs for ~1.5-3x faster CPU inference.
RUN pip install --no-cache-dir -r requirements.txt
COPY worker/*.py ./
COPY shared /srv/shared
RUN useradd -r -u 10002 worker && mkdir -p /data/store && chown -R worker /data
USER worker
CMD ["python", "worker.py"]
