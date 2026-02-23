#!/usr/bin/env bash
set -euo pipefail

curl -x http://localhost:8080 https://api.openai.com/v1/models -k

curl -x http://localhost:8080 https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"message":"test"}' -k
