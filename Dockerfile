FROM python:3.12-slim

LABEL maintainer="Efeberk"
LABEL description="SentinelAuth - Local identity tampering and integrity validation lab"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV FLASK_ENV=production
ENV SENTINEL_SECRET=change_this_in_production

CMD ["python", "run.py"]
