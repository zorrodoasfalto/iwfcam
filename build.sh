#!/usr/bin/env bash
set -euo pipefail
echo "Compilando IWFCam JT-B9 RTSP Bridge V17..."
go mod tidy
go build -trimpath -ldflags="-s -w" -o iwfcam-jtb9-v17 .
chmod +x iwfcam-jtb9-v17
echo "OK: ./iwfcam-jtb9-v17"
