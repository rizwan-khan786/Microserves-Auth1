# Use official Node LTS
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source
COPY . .

# Expose port
EXPOSE 3000

# Default env (can be overridden by docker-compose)
ENV NODE_ENV=production
CMD ["node", "src/app.js"]
