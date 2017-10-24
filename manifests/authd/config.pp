# @!visibility private
class sasl::authd::config {

  $socket                  = $::sasl::authd::socket
  $mechanism               = $::sasl::authd::mechanism
  $threads                 = $::sasl::authd::threads
  $caching                 = $::sasl::authd::caching
  $combine_realm           = $::sasl::authd::combine_realm
  $ldap_conf_file          = $::sasl::authd::ldap_conf_file
  $ldap_auth_method        = $::sasl::authd::ldap_auth_method
  $ldap_bind_dn            = $::sasl::authd::ldap_bind_dn
  $ldap_bind_pw            = $::sasl::authd::ldap_bind_pw
  $ldap_default_domain     = $::sasl::authd::ldap_default_domain
  $ldap_default_realm      = $::sasl::authd::ldap_default_realm
  $ldap_deref              = $::sasl::authd::ldap_deref
  $ldap_filter             = $::sasl::authd::ldap_filter
  $ldap_group_attr         = $::sasl::authd::ldap_group_attr
  $ldap_group_dn           = $::sasl::authd::ldap_group_dn
  $ldap_group_filter       = $::sasl::authd::ldap_group_filter
  $ldap_group_match_method = $::sasl::authd::ldap_group_match_method
  $ldap_group_search_base  = $::sasl::authd::ldap_group_search_base
  $ldap_group_scope        = $::sasl::authd::ldap_group_scope
  $ldap_password           = $::sasl::authd::ldap_password
  $ldap_password_attr      = $::sasl::authd::ldap_password_attr
  $ldap_referrals          = $::sasl::authd::ldap_referrals
  $ldap_restart            = $::sasl::authd::ldap_restart
  $ldap_id                 = $::sasl::authd::ldap_id
  $ldap_authz_id           = $::sasl::authd::ldap_authz_id
  $ldap_mech               = $::sasl::authd::ldap_mech
  $ldap_realm              = $::sasl::authd::ldap_realm
  $ldap_scope              = $::sasl::authd::ldap_scope
  $ldap_search_base        = $::sasl::authd::ldap_search_base
  $ldap_servers            = $::sasl::authd::ldap_servers
  $ldap_start_tls          = $::sasl::authd::ldap_start_tls
  $ldap_time_limit         = $::sasl::authd::ldap_time_limit
  $ldap_timeout            = $::sasl::authd::ldap_timeout
  $ldap_tls_check_peer     = $::sasl::authd::ldap_tls_check_peer
  $ldap_tls_cacert_file    = $::sasl::authd::ldap_tls_cacert_file
  $ldap_tls_cacert_dir     = $::sasl::authd::ldap_tls_cacert_dir
  $ldap_tls_ciphers        = $::sasl::authd::ldap_tls_ciphers
  $ldap_tls_cert           = $::sasl::authd::ldap_tls_cert
  $ldap_tls_key            = $::sasl::authd::ldap_tls_key
  $ldap_use_sasl           = $::sasl::authd::ldap_use_sasl
  $ldap_version            = $::sasl::authd::ldap_version
  $imap_server             = $::sasl::authd::imap_server

  $_mech_options = $::sasl::authd::mechanism ? {
    'ldap'  => $ldap_conf_file ? {
      $::sasl::params::saslauthd_ldap_conf_file => '',
      default                                   => $ldap_conf_file,
    },
    'rimap' => type($imap_server) ? {
      Type[Tuple] => "${imap_server[0]}/${imap_server[1]}",
      default     => $imap_server,
    },
    default => '',
  }

  if $caching {
    if $combine_realm {
      $_flags = '-c -r '
    } else {
      $_flags = '-c '
    }
  } else {
    if $combine_realm {
      $_flags = '-r '
    } else {
      $_flags = ''
    }
  }

  #notify { 'SaslauthdMech': withpath => true, name => "mechanism is '${mechanism}'." }
  #notify { 'SaslauthdThreads': withpath => true, name => "threads are '${threads}'." }

  case $::osfamily {
    'RedHat': {
      if size($_mech_options) > 0 {
        $mech_options = "-O ${_mech_options}"
      } else {
        $mech_options = '' # lint:ignore:empty_string_assignment
      }

      $flags = $threads ? {
        $::sasl::params::saslauthd_threads => strip("${_flags}${mech_options}"),
        default                            => strip("${_flags}${mech_options} -n ${threads}")
      }

      #notify { 'SaslauthdMechOpts': withpath => true, name => "mech options are '${mech_options}'." }
      #notify { 'SaslauthdFlags': withpath => true, name => "flags are '${flags}'." }

      file { '/etc/sysconfig/saslauthd':
        ensure  => file,
        owner   => 0,
        group   => 0,
        mode    => '0644',
        content => template('sasl/sysconfig.erb'),
      }
    }
    'Debian': {
      $mech_options = $_mech_options
      $flags = $_flags

      #notify { 'SaslauthdMechOpts': withpath => true, name => "mech options are '${mech_options}'." }
      #notify { 'SaslauthdFlags': withpath => true, name => "flags are '${flags}'." }

      file { '/etc/default/saslauthd':
        ensure  => file,
        owner   => 0,
        group   => 0,
        mode    => '0644',
        content => template('sasl/default.erb'),
      }
    }
    default: {
      # noop
    }
  }

  $ldap_conf_file_ensure = $::sasl::authd::mechanism ? {
    'ldap'  => file,
    default => absent,
  }

  file { $ldap_conf_file:
    ensure  => $ldap_conf_file_ensure,
    owner   => 0,
    group   => 0,
    mode    => '0644',
    content => template('sasl/saslauthd.conf.erb'),
  }
}
