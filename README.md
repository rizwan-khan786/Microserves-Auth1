# Auth Service

## Quick start (local)
1. Copy `.env.example` to `.env` and set values.
2. `npm install`
3. `npm run dev` (requires nodemon) or `npm start`

## Docker (standalone)
Build:
  docker build -t auth-service:latest .

Run (with proper env):
  docker run -p 3001:3000 --env-file .env auth-service:latest

## Endpoints
- POST /api/v1/auth/register  -> register user
- POST /api/v1/auth/login     -> login (returns access + refresh tokens)
- POST /api/v1/auth/refresh   -> get new access token using refresh token
- POST /api/v1/auth/logout    -> invalidate refresh token
- GET  /api/v1/auth/me        -> protected route (requires Authorization: Bearer <accessToken>)

## Notes
- This is a minimal but production-minded implementation. For high-scale (millions/min) move refresh tokens to Redis, use rotating tokens, implement device/session tracking, and use rate-limiting + WAF + API gateway + autoscaling.
# Microserves-Auth1
