# Image for the MCP tool servers and the attacker sink. Runs as an unprivileged
# user; in production the containers are also read-only with no internet access.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TOOL_HOST=0.0.0.0 \
    WORKSPACE_DIR=/sandbox CRM_DB=/data/crm.sqlite3
WORKDIR /app
COPY tools/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin tool \
 && mkdir -p /sandbox /data && chown 10001:10001 /sandbox /data
COPY tools/ /app/tools/
COPY attacker/ /app/attacker/
RUN rm -rf /app/tools/sandbox /app/tools/crm.sqlite3 /app/tools/__pycache__ /app/tools/test_workspace.py
USER 10001
CMD ["python", "tools/workspace_server.py"]
