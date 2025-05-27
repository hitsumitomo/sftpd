# Secure SFTP Server

A lightweight SFTP server with secure file transfers, no system user accounts required, per-user chroot isolation, and support for running scripts or commands via virtual SFTP paths ("exec" mappings). Easily automate server-side actions by uploading to special virtual files.

## Features

- Password and public key authentication
- Encrypted storage of sensitive config data
- Per-user chroot directories
- Filters out symlinks, sockets, and unreadable files
- "Exec" mappings: upload to a virtual path to execute a script
- Daemon mode and privilege dropping
- Graceful config reload (SIGHUP)

## Description

SFTP server for secure, isolated file access and automation. Users and permissions are managed in a single config file. Each user is restricted to their own virtual directories. Optionally, uploading to special virtual paths can trigger execution of predefined scripts on the server (with controlled privileges). No system accounts or shell access required.

## Requirements

- Linux, macOS, or other UNIX-like operating system
- Go 1.16+

## Quick Start

```bash
# Install
git clone https://github.com/hitsumitomo/sftpd.git
cd sftpd
make build SEED=random
sudo cp bin/sftpd /usr/local/bin/
```

**Note:** Always use a unique SEED value for each deployment. Never use the default or example seeds in production.

# Configure
```bash
ssh-keygen -t ed25519 -f server_key -N ""
```

# Create config file (see Configuration section)

# Run
```bash
sftpd -c /usr/local/etc/sftpd.conf
```

**Important:** On startup, the configuration file will be overwritten if it contains unencrypted sensitive fields (e.g., passwords, keys). Make sure to keep a secure backup if you need to retain the original unencrypted version.

## Installation

### From Source

**Important:** Before deploying the application, ensure the uniqueness of the seed values to enhance security. The deterministic encryption algorithm in `pkg/cipher/aead.go` uses fixed seeds for initialization, which can be a potential security risk if not replaced with random values or properly adjusted.

You can build the project with different seed configurations:

1. Clone and build with random seeds:
   ```bash
   git clone https://github.com/hitsumitomo/sftpd.git
   cd sftpd
   make build SEED=random
   ```

2. Build with a custom string, which will be used to derive deterministic seeds via SHA-256 hashing:
   ```bash
   make build SEED=aCustomStringHere
   ```

3. Use custom fixed seeds directly:
   ```bash
   make build SEED1=17384293841293847123 SEED2=3022513517701228024
   ```

**Warning:** Never use the same SEED or fixed seeds for multiple deployments. Always generate a unique SEED for each environment to ensure encryption keys are unique.

### Binary Installation

```bash
# Copy the binary to a system location
cp bin/sftpd /usr/local/bin/
```

## Configuration

Before configuring users with public key authentication, generate an SSH private key for the server:

```bash
# Ed25519 keys are recommended for their security and performance
ssh-keygen -t ed25519 -f server_key -N ""
```

This will create `server_key` (private key) and `server_key.pub` (public key) files.
Note: Only the private key (`server_key`) is required for the server configuration; the public key is not used.

**Tip:** Restrict permissions on your config and key files:
```bash
chmod 600 /usr/local/etc/sftpd.conf
chown root:root /usr/local/etc/sftpd.conf
```
If you embed the private key into the config and no longer need the original `server_key` or `server_key.pub` files, you may securely delete them after the first successful launch (when the config is encrypted).

Create a JSON configuration file at `/usr/local/etc/sftpd.conf`:

```json
{
    "addr": ":2222",
    "http": {
        "addr": ":8222",
        "url": "/X9p7r_QzT4k-Access",
        "username": "suP3rV!zor42",
        "password": "S9@_cR#3T.L0ck3r",
        "filter": {
            "whitelist": [ "192.168.99.0/24" ]
        }
    },
    "uid": 1001,
    "gid": 1000,
    "private": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZX...ktdjEAAAAABG5\n-----END OPENSSH PRIVATE KEY-----",
    "groups": {
        "devs": {
            "mapping": {
                "project": {
                    "path": "/srv/projects/demo",
                    "mode": "rw"
                },
                "tmp": {
                    "path": "/tmp",
                    "mode": "ro"
                },
            "filter": {
                "whitelist": [ "192.168.99.0/24" ]
            }
        }
    },
    "users": {
        "alice": {
            "password": "S3cretPassw0rd",
            "pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlqZ2xvcnlvdXNwdWJrZXlhbGljZQ==",
            "mapping": {
                "docs": {
                    "path": "/srv/docs",
                    "mode": "rw"
                },
                "tmp": {
                    "path": "/tmp",
                    "mode": "ro"
                }
            },
            "filter": {
                "whitelist": [ "10.0.0.0/8" ],
                "blacklist": [ "10.0.0.198", "10.0.0.12" ]
            }
        },
        "bob": {
            "password": "AnotherPass123",
            "pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJvYmJ5cHVibGlja2V5Ym9i",
            "mapping": {
                "web": {
                    "path": "/srv/web",
                    "mode": "rw"
                },
                "project": {
                    "path": "/srv/projects/demo",
                    "mode": "ro"
                },
                "tmp": {
                    "path": "/tmp",
                    "mode": "rw"
                }
            }
        },
        "carol": {
            "password": "CarolSecret",
            "pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNhcm9scHVibGlja2V5Y2Fyb2w=",
            "groups": [ "devs" ],
            "mapping": {
                "execute.rebuild": {
                    "path": "/usr/local/bin/rebuild.sh",
                    "mode": "exec"
                }
            }
        }
    }
}
```

- `addr`: The address and port to listen on.
- `uid` and `gid`: IDs to drop privileges to after binding; typically set to a non-root user.
- `private`: Server's SSH private key (will be automatically encrypted).
- `groups`: Named groups of directory mappings and IP filters. Each group can be assigned to users for shared access rules.
- `users`: Map of users with their credentials and settings.
  - `password`: User's password (will be automatically encrypted).
  - `pubkey`: User's public key (will be automatically encrypted).
  - `mapping`: Defines alias directories for the user's SFTP session. Each entry maps an alias (key) to a host path (`path`) with an access mode ("ro", "rw", or "exec").
    - If `mode` is `"exec"`, uploading a file to this alias will execute the script at the specified `path`.
    - **For exec mappings:** The result (combined stdout and stderr) of the executed command will be stored and can be read back by any subsequent read (e.g., `get`) from the same mapping path. This allows you to retrieve the output of the script or command by simply reading from the virtual file.
  - `groups`: List of group names from which to inherit mappings and filters.
  - `filter`: Optional IP whitelist/blacklist for user access.

> **Exec mode:** When a mapping has `"mode": "exec"`, uploading any file to the corresponding virtual path will execute the script at the specified `path` on the server (using the configured uid/gid). The combined output (stdout + stderr) of the command will be available for reading from the same mapping path. This allows for secure automation and remote script execution without shell access. `ExecTimeout` is 10 seconds by default and can be configured in `types.go`.

> **Important:** This SFTP server operates independently of system user accounts — users are defined in the configuration file and authenticated internally.

## Usage

> **Note:** The server must start as root to bind to privileged ports (<1024) and create log or PID files in restricted locations. After setting up listeners and opening these files, it drops to the configured `uid/gid` to continue running with reduced privileges.

### Starting the Server

```bash
sftpd -c /usr/local/etc/sftpd.conf -l /var/log/sftpd.log -p /run/sftpd.pid
```

Command-line options:
- `-c`: Path to the configuration file (default: `/usr/local/etc/sftpd.conf`)
- `-l`: Path to the log file (default: `/var/log/sftpd.log`)
- `-p`: Path to the PID file (default: `/run/sftpd.pid`)

### Connecting to the Server

```bash
# With password authentication
sftp -P 2222 username@server-address

# With SSH key authentication
# The server identifies users by the SHA-256 fingerprint of their public key, so you do not need to explicitly specify a username.
sftp -i /path/to/private.key -P 2222 server-address
```

**Note:** When using key authentication, the username is determined by the public key fingerprint, not the login name.

### Reloading Configuration

**Important:** Make sure the privileges (uid/gid) are sufficient to overwrite the config.
Send a SIGHUP signal to reload the configuration without restarting:

```bash
kill -HUP $(cat /run/sftpd.pid)
```

## Web Configurator

A web-based configuration interface is also available: ![image](images/web.png)

## Security Considerations

- Private keys and passwords in the configuration are automatically encrypted (after the first run)
- The server drops privileges after binding to the port
- The server runs as a daemon by default
- Authentication mechanisms follow SSH standards
- System user accounts are not required for SFTP users, as authentication is handled internally
- Logging is minimal by default. Feel free to extend or customize it as needed.
- **Always** use unique seeds and protect your configuration and key files with strict permissions.

### Offline Environment Notes
If the sftpd server operates in an offline/air-gapped environment:
- All web dependencies (Bootstrap, Vue.js) must be locally embedded — CDN resources will not be available.
- Download these dependencies during deployment preparation:
  - [Bootstrap](https://getbootstrap.com/docs/5.3/getting-started/download/)
  - [Vue.js](https://vuejs.org/guide/quick-start.html#without-build-tools)
- Store them in your project's static assets directory

