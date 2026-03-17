module.exports = {
  apps: [{
    name: 'onlinebakala',
    script: 'server.js',
    cwd: '/home/ec2-user/onlinebakala',
    env: {
      NODE_ENV: 'production',
      PORT: 3000,
      DB_HOST: 'netflix-production-db.c76msgoueoc9.eu-west-1.rds.amazonaws.com',
      DB_USER: 'admin',
      DB_PASS: 'Bakala2026pwd',
      DB_NAME: 'netflix',
      JWT_SECRET: 'bakala_super_secret_jwt_key_2026_change_this',
      COOKIE_SECRET: 'bakala_cookie_secret_2026'
    }
  }]
};
