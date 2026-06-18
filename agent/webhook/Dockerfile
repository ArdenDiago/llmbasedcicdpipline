FROM node:20-slim

WORKDIR /app

COPY agent/webhook/package.json .
RUN npm install --production

COPY agent/webhook/ .

EXPOSE 3000

CMD ["node", "server.js"]
