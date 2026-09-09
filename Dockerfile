FROM node:22.16.0-bookworm

# Install Chrome

RUN echo 'deb http://dl.google.com/linux/chrome/deb/ stable main' > /etc/apt/sources.list.d/chrome.list

RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -

RUN set -x \
    && apt-get update \
    && apt-get install -y \
        google-chrome-stable

ENV CHROME_BIN /usr/bin/google-chrome

# Pin npm to the exact version recorded in package.json's packageManager
# field, the same way CI's use_node step does (bitcore-migration-plan.md
# target design item 3/4).
RUN npm install -g npm@10.9.2

# Log versions

RUN set -x \
    && node -v \
    && npm -v \
    && google-chrome --version

WORKDIR /bitcore

ADD . .

# Preflight before any install machinery runs; root preinstall re-checks
# this too, but is not a substitute for it (bitcore-acceptance-spec.md §3).
RUN node scripts/workspaces/check-runtime.cjs

RUN npm ci --foreground-scripts
