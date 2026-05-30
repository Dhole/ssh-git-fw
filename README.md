# ssh-git-fw

**Work In Progress**

A proxy for git over ssh that acts as a firewall for sandbox environments.

The goal of this project is to enable development environments to run in a sandbox with restricted access to the host resources, particularly without access to ssh keys, while still allowing for git workflows.  The idea is that the git process running inside the sandbox uses a proxy that runs on the host for ssh access.  The proxy intercepts the git over ssh messages and implements a fine grained permissions system like:
- Per repository configuration
    - Read permission
    - Write permission
- Interactive permissions via pop-up window
- Stored permissions via toml configuration file

# Status

Currently the repository is just a skeleton of a server that accepts ssh connections over socks5 and shows logs of what's happening.
