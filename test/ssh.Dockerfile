FROM alpine:3.22

RUN apk add --no-cache openssh git

COPY <<EOF /etc/ssh/ssh_host_ed25519_key
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzFWaPfYlKCVpUWu1Bs+P74nDGdC32caXKyPxI5nNbkgAAAJD155769eee
+gAAAAtzc2gtZWQyNTUxOQAAACCzFWaPfYlKCVpUWu1Bs+P74nDGdC32caXKyPxI5nNbkg
AAAEAyfU/BD1GN5fyvb5xws7tKn7MCVJt5jU5U7ljxyk0F/rMVZo99iUoJWlRa7UGz4/vi
cMZ0LfZxpcrI/Ejmc1uSAAAACXJuZEByYXZlbgECAwQ=
-----END OPENSSH PRIVATE KEY-----
EOF

COPY <<EOF /etc/ssh/ssh_host_ed25519_key.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMVZo99iUoJWlRa7UGz4/vicMZ0LfZxpcrI/Ejmc1uS
EOF

RUN adduser -D -s /usr/bin/git-shell git

RUN mkdir /home/git/.ssh
COPY <<EOF /home/git/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c
EOF

RUN mkdir /git
RUN cd /git && \
    chown -R git:git . && \
    chmod -R ug+rwX .

USER git

RUN cd /git && \
    git init --bare test1.git && \
    git init --bare test2.git


WORKDIR /git/

# SHA256:aZG8acRY2b1AeZG9UhEIjWUL/HfPzcaaXs+Bze7zUa4

ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
