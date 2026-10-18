# Image for every Bayora zone container (red, blue, broker, mock model). Code is mounted read-only at /app;
# containers run as uid 65534 via --user in bayora/run.py.
FROM python:3.12-slim
