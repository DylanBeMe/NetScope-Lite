# syntax=docker/dockerfile:1.7

FROM node:25-bookworm-slim AS dependencies
WORKDIR /app

# better-sqlite3 normally downloads a prebuilt binary. These tools provide a
# deterministic fallback when a binary is not available for the target platform.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund \
    && npm cache clean --force

FROM node:25-bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping net-tools tini \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data \
    && chown node:node /data

ENV NODE_ENV=production \
    NETSCOPE_DATA_DIR=/data \
    NETSCOPE_HOST=127.0.0.1 \
    NETSCOPE_PORT=8787 \
    NETSCOPE_ALLOW_NON_LOOPBACK=0

COPY --from=dependencies --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json server.js LICENSE ./
COPY --chown=node:node src ./src
COPY --chown=node:node static ./static

USER node
VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "const http=require('node:http');const req=http.get({host:'127.0.0.1',port:8787,path:'/healthz',headers:{host:'127.0.0.1'}},res=>process.exit(res.statusCode===200?0:1));req.setTimeout(3000,()=>{req.destroy();process.exit(1)});req.on('error',()=>process.exit(1));"]

ENTRYPOINT ["tini", "--"]
CMD ["node", "server.js"]
