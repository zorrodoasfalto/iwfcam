V17 - recuperação interna, sem cron/ffmpeg externo

Sintoma da V16:
- RTSP continua respondendo DESCRIBE/SETUP/PLAY;
- a sessão UDP/P2P da câmera deixa de produzir H264;
- PM2 não detecta porque o processo continua vivo.

Correção:
- o servidor RTSP é criado uma vez e continua ouvindo em 7554;
- a V17 mede o último frame H264 válido realmente publicado;
- se ficar 15s sem H264, encerra APENAS a sessão P2P;
- envia stop/close;
- fecha/reabre o UDP;
- refaz discovery, cloud rendezvous, handshake e START_STREAM;
- o processo não precisa ser reiniciado;
- a URL RTSP não muda.

Build:
  chmod +x build.sh run.sh
  ./build.sh

PM2:
  pm2 start ecosystem.config.cjs --name iwfcam-1
  pm2 save

RTSP:
  rtsp://192.168.1.12:7554/cam
