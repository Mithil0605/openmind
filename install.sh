#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if ! command -v node >/dev/null 2>&1; then
  echo "Setup stopped: Node.js 22 or newer is required. Install Node.js from https://nodejs.org/ and run this setup again."
  exit 1
fi
node ./install.mjs
