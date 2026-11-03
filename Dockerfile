FROM node:20-alpine
# iputils ให้คำสั่ง ping ที่รายงานเวลาแม่นยำ
RUN apk add --no-cache iputils tzdata
ENV TZ=Asia/Bangkok NODE_ENV=production PORT=3000 DATA_DIR=/data
WORKDIR /app
COPY package.json server.js ./
COPY public ./public
VOLUME ["/data"]
EXPOSE 3000
CMD ["node", "server.js"]
