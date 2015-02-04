[![Build Status](https://travis-ci.org/express42/knife-openvpn.svg)](https://travis-ci.org/express42/knife-openvpn)

# knife-openvpn
## Description
A knife plugin for [Express 42 OpenVPN cookbook].

## Installation
This plugin is distributed as a Ruby Gem. To install it, run:

`gem install knife-openvpn`

## Basic Examples

Create server ca, server cert, server key and dh params:

`knife openvpn server create office`

Add openvpn client:

`knife openvpn user create office john`

Export client data (.ovpn config, server ca, client cert and key):

`knife openvpn user export office john`

Revoke access:

`knife openvpn user revoke office john`

## License and Maintainer

Maintainer:: LLC Express 42 (<cookbooks@express42.com>)

License:: MIT

[Express 42 OpenVPN cookbook]: https://github.com/express42-cookbooks/openvpn
