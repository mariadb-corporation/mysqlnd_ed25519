# mysqlnd_ed25519 plugin

A **mysqlnd authentication plugin** providing **Ed25519-based authentication** for PHP when connecting to MariaDB servers.

## Why?

PHP currently connects to MariaDB servers using `mysql_native_password`, which relies on **SHA1**, a deprecated and insecure algorithm.

**Ed25519** provides modern, secure, and fast public-key authentication, helping to eliminate SHA1 usage in your PHP–MariaDB connections.

## Features

- **Ed25519 authentication** using [libsodium](https://libsodium.org/).
- Drop-in authentication plugin for **mysqlnd**.
- Supports MariaDB servers configured with the `ed25519` authentication plugin.

## Requirements

- PHP 8.1 or newer with `mysqlnd`.
- `libsodium` development libraries.
- MariaDB server configured with `ed25519` authentication plugin. (version 10.4.3 or newer)

## Installation

### Normal installation

`mysqlnd_ed25519` is usually built and installed automatically when installed through your system’s PHP extension packaging system.

Note: When installed into PHP’s extension directory, `mysqlnd_ed25519` is loaded automatically by `mysqlnd`.
You do not need to add `extension=mysqlnd_ed25519 to your php.ini.

### Building from source

If you cloned the repository or want to build manually:

```bash
phpize
./configure
make
sudo make install

