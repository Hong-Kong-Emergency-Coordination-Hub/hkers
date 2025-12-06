#!/bin/sh
# Generate a secure random session secret
# Usage: ./scripts/generate-secret.sh

openssl rand -base64 32

