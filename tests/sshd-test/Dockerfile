FROM linuxkit/sshd:62036c2a279715d05e8298b9269a0659964f2619-amd64

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apk add openssh-sftp-server=9.1_p1-r5

# hadolint ignore=DL3006
RUN echo 'root:root' |chpasswd

RUN sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
RUN sed -ri 's/UsePAM yes/#UsePAM yes/g' /etc/ssh/sshd_config
RUN sed -ri 's/^#?PasswordAuthentication.*$/PasswordAuthentication yes/g' /etc/ssh/sshd_config
RUN sed -ri 's/^#Subsystem/Subsystem/g' /etc/ssh/sshd_config

COPY ssh_host_ed25519_key ssh_host_ed25519_key.pub /etc/ssh/
COPY authorized_keys /root/.ssh/authorized_keys

RUN chmod 600 ~/.ssh/authorized_keys
