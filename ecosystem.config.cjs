module.exports = {
  apps: [
    {
      name: "iwfcam-1",
      cwd: "/home/leandro/www/iwfcam",
      script: "./iwfcam-jtb9-v17",
      interpreter: "none",
      args: [
        "--ip", "192.168.2.3",
        "--stream-port", "0",
        "--local-port", "36891",
        "--rtsp-port", "7554",
        "--media-timeout", "15",
        "--reconnect-delay", "3"
      ],
      autorestart: true,
      restart_delay: 5000,
      max_restarts: 100000,
      time: true
    }
  ]
};
