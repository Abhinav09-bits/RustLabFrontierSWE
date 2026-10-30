FROM python:3.12.8-slim-bookworm

RUN useradd --create-home --shell /bin/bash --uid 1000 agent \
    && mkdir -p /app \
    && chown agent:agent /app

COPY grade.py /root/tests/grade.py
COPY test.sh /tests/test.sh
COPY test.sh /root/tests/test.sh
RUN chown -R root:root /root/tests /tests \
    && chmod 700 /root /root/tests /tests \
    && chmod 700 /root/tests/grade.py /root/tests/test.sh /tests/test.sh

WORKDIR /app
