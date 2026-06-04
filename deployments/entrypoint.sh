#!/bin/sh
set -e

/iam-server &
IAM_PID=$!

until /seed-user \
    -email "${ADMIN_EMAIL}" \
    -password "${ADMIN_PASSWORD}" \
    -name "${ADMIN_NAME}" \
    -username "${ADMIN_USERNAME}" \
    -admin 2>/dev/null; do
    echo "...waiting for DB to be ready"
    sleep 2
done

wait $IAM_PID
