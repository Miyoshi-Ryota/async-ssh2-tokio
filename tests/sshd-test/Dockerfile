FROM docker.io/ubuntu:24.04

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Warsaw

RUN apt-get update && \
    apt-get install -y openssh-server openssh-sftp-server vim && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# hadolint ignore=DL3006
RUN echo 'root:root' |chpasswd

RUN sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
RUN sed -ri 's/^#?PasswordAuthentication.*$/PasswordAuthentication yes/g' /etc/ssh/sshd_config
RUN sed -ri 's/^#?KbdInteractiveAuthentication.*$/KbdInteractiveAuthentication yes/g' /etc/ssh/sshd_config

RUN mkdir /var/run/sshd

COPY ssh_host_ed25519_key ssh_host_ed25519_key.pub /etc/ssh/
COPY authorized_keys /root/.ssh/authorized_keys

RUN chmod 600 ~/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
