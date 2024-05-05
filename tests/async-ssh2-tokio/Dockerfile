FROM rust:1.71.0

ENV ASYNC_SSH2_TEST_HOST_IP=10.10.10.2
ENV ASYNC_SSH2_TEST_HOST_USER=root
ENV ASYNC_SSH2_TEST_HOST_PW=root
ENV ASYNC_SSH2_TEST_CLIENT_PRIV=/root/.ssh/id_ed25519
ENV ASYNC_SSH2_TEST_CLIENT_PROT_PRIV=/root/.ssh/prot.id_ed25519
ENV ASYNC_SSH2_TEST_CLIENT_PROT_PASS=test
ENV ASYNC_SSH2_TEST_SERVER_PUB=/root/server.ed25519.pub
ENV ASYNC_SSH2_TEST_HOST_PORT=22
ENV ASYNC_SSH2_TEST_HOST_NAME=ssh-server
ENV ASYNC_SSH2_TEST_KNOWN_HOSTS=/root/.ssh/known_hosts
ENV ASYNC_SSH2_TEST_UPLOAD_FILE=/async-ssh2-tokio/tests/async-ssh2-tokio/test-upload-file

COPY tests/async-ssh2-tokio/id_ed25519 /root/.ssh/id_ed25519
COPY tests/async-ssh2-tokio/id_ed25519.pub /root/.ssh/id_ed25519.pub
COPY tests/async-ssh2-tokio/prot.id_ed25519 /root/.ssh/prot.id_ed25519
COPY tests/async-ssh2-tokio/prot.id_ed25519.pub /root/.ssh/prot.id_ed25519.pub
COPY tests/async-ssh2-tokio/server.ed25519.pub /root/server.ed25519.pub
COPY tests/async-ssh2-tokio/known_hosts /root/.ssh/known_hosts

WORKDIR /async-ssh2-tokio
COPY . .
