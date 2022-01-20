#!/bin/bash
docker-compose -f ./tests/docker-compose.yml up -d
docker-compose -f ./tests/docker-compose.yml exec -T async-ssh2-tokio cargo test
