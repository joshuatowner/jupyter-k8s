#!/usr/bin/env python3
import jwt
import time

# Read JWT signing key from .env
with open('.env', 'r') as f:
    for line in f:
        if line.startswith('JWT_SIGNING_KEY='):
            signing_key = line.split('=', 1)[1].strip()
            break

# JWT configuration from authmiddleware
issuer = "jupyter-k8s-auth"
audience = "workspace-users"

# Token claims - use Unix timestamps
now = int(time.time())
exp_time = now + 300  # 5 minutes from now

payload = {
    "iss": issuer,
    "aud": audience,
    "sub": "test-user",
    "path": "/workspaces/jupyter-k8s-hyperpod/workspace-hyperpod",
    "domain": "k8s-jupyterk-traefik-8f58aa93ad-336bffb9db7f7f28.elb.us-west-2.amazonaws.com",
    "tokenType": "bootstrap",
    "exp": exp_time,
    "iat": now,
    "nbf": now - 60,  # Valid from 1 minute ago to handle clock skew
    "user": "test-user",
    "groups": ["users"]
}

# Generate JWT with signing key
token = jwt.encode(payload, signing_key, algorithm="HS256")
print(f"Generated JWT token: {token}")
print(f"Valid from: {now - 60} (nbf)")
print(f"Expires at: {exp_time} (exp)")
print(f"Current time: {now}")
