#!/usr/bin/env bash
set -euo pipefail
exec ./iwfcam-jtb9-v17 \
  --ip 192.168.2.3 \
  --stream-port 0 \
  --local-port 36891 \
  --rtsp-port 7554 \
  --media-timeout 15 \
  --reconnect-delay 3
