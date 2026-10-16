# Multi-stage build for web application
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies with lockfile
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Copy web source and compile production bundle
COPY frontend/ ./
RUN npm run build

# Production runtime with Nginx
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
