#!/bin/bash
mkdir -p /logs/verifier
chmod 700 /logs/verifier
export SEGLOG_AS_USER=agent
python3 /root/tests/grade.py
status=$?
if [ "$status" -eq 0 ]; then
  printf '1\n' > /logs/verifier/reward.txt
else
  printf '0\n' > /logs/verifier/reward.txt
fi
chmod 600 /logs/verifier/reward.txt
exit 0
