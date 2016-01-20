## rust-capabilities [![Build Status](https://travis-ci.org/gcmurphy/rust-capabilities.svg)](https://travis-ci.org/gcmurphy/rust-capabilities)
---

### About

Provides a rust interface to [Linux Capabilties](https://www.kernel.org/pub/linux/libs/security/linux-privs/kernel-2.2/capfaq-0.2.txt).

### Installation

Requires libcap to be installed on the machine.

#### Fedora

    $ sudo dnf install libcap-devel

#### Debian/Ubuntu

    $ sudo apt-get install libcap-dev


### Usage

See examples/demo.rs for example usage.

    $ cargo run --example demo
