#!/bin/bash

# change to script dir
cd "${0%/*}" || exit 1

./generate_test_keys.sh || exit 1

cd ..

docker compose -f ./tests/docker-compose.yml build --no-cache || exit 1

docker compose -f ./tests/docker-compose.yml up -d || exit 1

docker compose -f ./tests/docker-compose.yml exec -T async-ssh2-tokio cargo test -- --test-threads=2
RET=$?

docker compose -f ./tests/docker-compose.yml down

exit $RET
