FROM node:24-alpine
WORKDIR /app
COPY --chown=node:node server.mjs cabinet-worker.mjs ./
USER node
ENV NODE_ENV=production PORT=8080
EXPOSE 8080
CMD ["node", "server.mjs"]
