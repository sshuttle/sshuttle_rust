# sshuttle-rust

## About

sshuttle-rust is a a rewrite of sshuttle, with the following features:

* It is written in rust, not Python.
* It talks to ssh using the "ssh -D" socks support, as a result it does not require any additional code on server.
* It should be considered alpha quality. While it works, there are many missing features.

Features that are implemented:

* IPv4 and IPv6.
* TCP support.
* socks5 support.
* nat firewall support.
* TPROXY firewall support.

Missing features include, but not limited to:

* Other firewalls, such as OSX support (should be easy to add, just not been a priority).
* UDP support (see below).
* DNS support (see below).
* Daemon support.

Known bugs:

* After starting process, initial connections will be rejected because ssh hasn't started yet.
* Some servers may support running remote programs, but might disallow -D port forwarding.
* Shutdown of run_client code could be a bit cleaner.
* Probably many others.

## Usage

```sh
sudo RUST_LOG=trace SSH_AUTH_SOCK="$SSH_AUTH_SOCK" sshuttle_rust --remote user@host.example.org --listen 127.0.0.1:1021  --listen '[::1]:1022' 0.0.0.0/0:443 '[::/0]:443'
```

This will create a ssh connection to "use@host.example.org" using "-D" and forward all connections to port 443. By default ssh is configured with `-D 127.0.0.1:1080`, the socks address can be changed with the `--socks` option.

If you omit the `--remote` option it will not start ssh, but try to connect to an existing socks server at the address given by the `--socks` option.

Alternative, possibly better usage:

```sh
ssh -D1080 -N user@host.example.org
sudo RUST_LOG=trace SSH_AUTH_SOCK="$SSH_AUTH_SOCK" sshuttle_rust --socks 127.0.0.1:1080 --listen 127.0.0.1:1021  --listen '[::1]:1022' 0.0.0.0/0:443 '[::/0]:443'
```

## UDP/DNS notes

Unfortunately Socks5 support for UDP involves sending UDP packets to a specified UDP port on the server.
Plus openssh does not have UDP support on its socks server, and does not allow forwarding of UDP packets.

These limitations mean it is not practical to implement a UDP solution that forwards packets over UDP, so
as I result this has not been implemented.

In the future, if anybody wanted to write the code, we could:

* Implement server side code, similar to the Python sshuttle.
* Implement a UDP DNS proxy that forwards all DNS requests using TCP.
