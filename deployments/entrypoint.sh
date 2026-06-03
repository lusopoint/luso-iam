#!/bin/sh
set -e

/iam-server &
IAM_PID=$!

# wait until db is ready to populate
until /seed-user -email "${ADMIN_EMAIL}" -password "${ADMIN_PASSWORD}" -admin 1 -name "${ADMIN_NAME}" 2>/dev/null; do
    echo "...waiting for DB to be ready"
    sleep 2
done

wait $IAM_PID
