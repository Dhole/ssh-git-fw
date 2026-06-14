# proxy-fw-ssh

**Work In Progress**

An ssh proxy that acts as a firewall for sandbox environments.  For now it supports firewall rules for the git protocol.

The goal of this project is to enable development environments to run in a sandbox with restricted access to the host resources, particularly without access to ssh keys, while still allowing for git workflows.  The idea is that the git process running inside the sandbox uses a proxy that runs on the host for ssh access.  The proxy intercepts the git over ssh messages and implements a fine grained permissions system like:
- Per repository configuration
    - Read permission
    - Write permission
- Interactive permissions via pop-up window
- Stored permissions via toml configuration file

# Status

Currently the repository is just a skeleton of a server that accepts ssh connections over socks5 and shows logs of what's happening.

# Testing

Build the docker image:
```
cd tests
sudo docker build --tag ssh-git-test -f ssh.Dockerfile .
```

Run the docker ssh server with hardcoded keys (Stop with Ctrl+C):
```
sudo docker run -p 2222:22 --init ssh-git-test
```

Make a local repository and configure the remote:
```
git remote add [git@127.0.0.1:2222]:/git/test.git origin
```

Then use the proxy:
```
GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/tmp/proxy-ssh-known_hosts -o ProxyCommand='ncat --proxy 127.0.0.1:2324 --proxy-type socks5 %h %p'" git push origin main
```
