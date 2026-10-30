FROM python:3.12.8-slim-bookworm

RUN useradd --create-home --shell /bin/bash --uid 1000 agent

COPY workspace/ /app/
RUN chown -R agent:agent /app

WORKDIR /app
