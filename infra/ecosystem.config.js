// PM2 ecosystem for Privex.
// Copy to repo root as ecosystem.config.js (gitignored).
// Usage: pm2 start ecosystem.config.js
//         pm2 startOrReload ecosystem.config.js --update-env
module.exports = {
  apps: [
    {
      name: "privex-api",
      script: "./server/target/release/privex-server",
      cwd: "/home/sonix/Privex",
      env_file: "/home/sonix/Privex/.env",
      // PVX-05: deploy.sh applies migrations via `privex-server migrate`, so the
      // serving process must NOT migrate on boot (avoids a restart racing the
      // migrator; matches the K8s Deployment which sets the same flag).
      env: { PRIVEX_SKIP_MIGRATIONS: "1" },
      max_restarts: 10,
      min_uptime: "10s",
      kill_timeout: 5000,
      error_file: "logs/privex-api-error.log",
      out_file: "logs/privex-api.log",
      merge_logs: true,
      log_date_format: "YYYY-MM-DD HH:mm:ss",
      autorestart: true,
      watch: false,
    },
  ],
};
