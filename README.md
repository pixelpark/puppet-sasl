# sasl

[![Build Status](https://travis-ci.org/bodgit/puppet-sasl.svg?branch=master)](https://travis-ci.org/bodgit/puppet-sasl)
[![Codecov](https://img.shields.io/codecov/c/github/bodgit/puppet-sasl)](https://codecov.io/gh/bodgit/puppet-sasl)
[![Puppet Forge version](http://img.shields.io/puppetforge/v/bodgit/sasl)](https://forge.puppetlabs.com/bodgit/sasl)
[![Puppet Forge downloads](https://img.shields.io/puppetforge/dt/bodgit/sasl)](https://forge.puppetlabs.com/bodgit/sasl)
[![Puppet Forge - PDK version](https://img.shields.io/puppetforge/pdk-version/bodgit/sasl)](https://forge.puppetlabs.com/bodgit/sasl)

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with sasl](#setup)
    * [What sasl affects](#what-sasl-affects)
    * [Beginning with sasl](#beginning-with-sasl)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Description

This module manages Cyrus SASL.

## Setup

### What sasl affects

This module can install per-application SASL configuration, automatically
pulling in any additional packages to provide the required authentication
methods. It can also manage saslauthd if that is the chosen mechanism along
with its own configuration options.

### Beginning with sasl

In the very simplest case, you can just include the following:

```puppet
include ::sasl
```

## Usage

To configure Postfix for `DIGEST-MD5` and `CRAM-MD5` authentication using the
sasldb backend:

```puppet
include ::sasl

::sasl::application { 'smtpd':
  pwcheck_method => 'auxprop',
  auxprop_plugin => 'sasldb',
  mech_list      => ['digest-md5', 'cram-md5'],
}
```

To configure Postfix for `PLAIN` and `LOGIN` authentication using the saslauthd
backend which itself is using LDAP+STARTTLS:

```puppet
include ::sasl

class { '::sasl::authd':
  mechanism           => 'ldap',
  ldap_auth_method    => 'bind',
  ldap_search_base    => 'ou=people,dc=example,dc=com',
  ldap_servers        => ['ldap://ldap.example.com'],
  ldap_start_tls      => true,
  ldap_tls_cacert_dir => '/etc/pki/tls/certs',
  ldap_tls_ciphers    => 'AES256',
}

::sasl::application { 'smtpd':
  pwcheck_method => 'saslauthd',
  mech_list      => ['plain', 'login'],
}
```

## Reference

The reference documentation is generated with
[puppet-strings](https://github.com/puppetlabs/puppet-strings) and the latest
version of the documentation is hosted at
[https://bodgit.github.io/puppet-sasl/](https://bodgit.github.io/puppet-sasl/)
and available also in the [REFERENCE.md](https://github.com/bodgit/puppet-sasl/blob/master/REFERENCE.md).

## Limitations

This module has been built on and tested against Puppet 5 and higher.

The module has been tested on:

* RedHat Enterprise Linux 6/7
* Ubuntu 14.04/16.04
* Debian 8

## Development

The module relies on [PDK](https://puppet.com/docs/pdk/1.x/pdk.html) and has
both [rspec-puppet](http://rspec-puppet.com) and
[beaker-rspec](https://github.com/puppetlabs/beaker-rspec) tests. Run them
with:

```
$ bundle exec rake spec
$ PUPPET_INSTALL_TYPE=agent PUPPET_INSTALL_VERSION=x.y.z bundle exec rake beaker:<nodeset>
```

Please log issues or pull requests at
[github](https://github.com/bodgit/puppet-sasl).
