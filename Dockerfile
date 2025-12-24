FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt .

# Upgrade pip first
RUN pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Place entrypoint outside bind-mounted /app to avoid CRLF/permission issues
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
