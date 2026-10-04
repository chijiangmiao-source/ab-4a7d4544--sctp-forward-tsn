FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY app ./app
COPY tests ./tests

# 构建期检查：全部源码须可编译
RUN python -m compileall -q app tests && mkdir -p /data/audits

ENV AUDIT_DATA_DIR=/data/audits \
    PORT=8080

EXPOSE 8080

CMD ["python", "-m", "app.server"]
