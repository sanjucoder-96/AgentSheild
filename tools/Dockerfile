# Image for the mock MCP tool servers and the attacker sink.
FROM python:3.12-slim
WORKDIR /app
COPY tools/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY tools/ /app/tools/
COPY attacker/ /app/attacker/
ENV TOOL_HOST=0.0.0.0
# override CMD per service in docker-compose
CMD ["python", "tools/workspace_server.py"]
