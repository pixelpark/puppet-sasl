# Installs and manages the SASL `saslauthd` daemon.
#
# @example Declaring the class using PAM mechanism
#   include ::sasl
#   class { '::sasl::authd':
#     mechanism => 'pam',
#   }
#
# @example Declaring the class using LDAP mechanism
#   include ::sasl
#   class { '::sasl::authd':
#     mechanism           => 'ldap',
#     ldap_auth_method    => 'bind',
#     ldap_search_base    => 'ou=people,dc=example,dc=com',
#     ldap_servers        => ['ldap://ldap.example.com'],
#     ldap_start_tls      => true,
#     ldap_tls_cacert_dir => '/etc/pki/tls/certs',
#     ldap_tls_ciphers    => 'AES256',
#   }
#
# @example Declaring the class using IMAP mechanism
#   include ::sasl
#   class { '::sasl::authd':
#     mechanism   => 'rimap',
#     imap_server => 'imap.example.com',
#   }
#
# @param mechanism The mechanism `saslauthd` uses to test the user credentials.
# @param threads Maximum number of concurrent threads to use.
# @param package_name The name of the package.
# @param service_name The name of the service.
# @param socket Path to the socket used for communication.
# @param hasstatus If the service supports querying the running status or not.
# @param ldap_conf_file Path to the configuration file for LDAP configuration,
#   usually `/etc/saslauthd.conf`.
# @param ldap_auth_method How to authenticate with the LDAP server.
# @param ldap_bind_dn Distinguished name used to bind to the LDAP server.
# @param ldap_bind_pw Password used to bind with.
# @param ldap_default_domain
# @param ldap_default_realm
# @param ldap_deref
# @param ldap_filter Search filter to apply when searching for users.
# @param ldap_group_attr
# @param ldap_group_dn
# @param ldap_group_filter Search filter to apply when searching for groups.
# @param ldap_group_match_method
# @param ldap_group_search_base Base used for searching for group entries.
# @param ldap_group_scope Search scope used when searching for group entries.
# @param ldap_password
# @param ldap_password_attr
# @param ldap_referrals
# @param ldap_restart
# @param ldap_id
# @param ldap_authz_id
# @param ldap_mech
# @param ldap_realm
# @param ldap_scope Search scope used when searching for user entries.
# @param ldap_search_base Base used for searching for user entries.
# @param ldap_servers List of LDAP URI's to query.
# @param ldap_start_tls Whether to use SSL/TLS.
# @param ldap_time_limit Search time limit.
# @param ldap_timeout Timeout when connecting to LDAP server.
# @param ldap_tls_check_peer Whether to verify the LDAP server certificate.
# @param ldap_tls_cacert_file Path to CA certificate.
# @param ldap_tls_cacert_dir Path to directory of CA certificates.
# @param ldap_tls_ciphers A list of accepted ciphers to use.
# @param ldap_tls_cert Path to client certificate.
# @param ldap_tls_key Path to client key.
# @param ldap_use_sasl Whether to use SASL with LDAP.
# @param ldap_version The LDAP protocol version to use, either 2 or 3.
# @param imap_server IMAP server to use, either specify a hostname/IP address
#   or hostname/IP address and port tuple.
#
# @see puppet_classes::sasl ::sasl
# @see puppet_defined_types::sasl::application ::sasl::application
class sasl::authd (
  SASL::Authd::Mechanism                              $mechanism,
  Integer[1]                                          $threads                 = $::sasl::params::saslauthd_threads,
  String                                              $package_name            = $::sasl::params::saslauthd_package,
  String                                              $service_name            = $::sasl::params::saslauthd_service,
  Stdlib::Absolutepath                                $socket                  = $::sasl::params::saslauthd_socket,
  Boolean                                             $hasstatus               = $::sasl::params::saslauthd_hasstatus,
  Boolean                                             $caching                 = $::sasl::params::saslauthd_caching,
  Boolean                                             $combine_realm           = $::sasl::params::combine_realm,
  # ldap
  Optional[Stdlib::Absolutepath]                      $ldap_conf_file          = $::sasl::params::saslauthd_ldap_conf_file,
  Optional[Enum['bind', 'custom', 'fastbind']]        $ldap_auth_method        = undef,
  Optional[Bodgitlib::LDAP::DN]                       $ldap_bind_dn            = undef,
  Optional[String]                                    $ldap_bind_pw            = undef,
  Optional[String]                                    $ldap_default_domain     = undef,
  Optional[String]                                    $ldap_default_realm      = undef,
  Optional[Enum['search', 'find', 'always', 'never']] $ldap_deref              = undef,
  Optional[Bodgitlib::LDAP::Filter]                   $ldap_filter             = undef,
  Optional[String]                                    $ldap_group_attr         = undef,
  Optional[Bodgitlib::LDAP::DN]                       $ldap_group_dn           = undef,
  Optional[Bodgitlib::LDAP::Filter]                   $ldap_group_filter       = undef,
  Optional[Enum['attr', 'filter']]                    $ldap_group_match_method = undef,
  Optional[Bodgitlib::LDAP::DN]                       $ldap_group_search_base  = undef,
  Optional[Bodgitlib::LDAP::Scope]                    $ldap_group_scope        = undef,
  Optional[String]                                    $ldap_password           = undef,
  Optional[String]                                    $ldap_password_attr      = undef,
  Optional[Boolean]                                   $ldap_referrals          = undef,
  Optional[Boolean]                                   $ldap_restart            = undef,
  Optional[String]                                    $ldap_id                 = undef,
  Optional[String]                                    $ldap_authz_id           = undef,
  Optional[String]                                    $ldap_mech               = undef,
  Optional[String]                                    $ldap_realm              = undef,
  Optional[Bodgitlib::LDAP::Scope]                    $ldap_scope              = undef,
  Optional[Bodgitlib::LDAP::DN]                       $ldap_search_base        = undef,
  Optional[Array[Bodgitlib::LDAP::URI::Simple, 1]]    $ldap_servers            = undef,
  Optional[Boolean]                                   $ldap_start_tls          = undef,
  Optional[Integer[0]]                                $ldap_time_limit         = undef,
  Optional[Integer[0]]                                $ldap_timeout            = undef,
  Optional[Boolean]                                   $ldap_tls_check_peer     = undef,
  Optional[Stdlib::Absolutepath]                      $ldap_tls_cacert_file    = undef,
  Optional[Stdlib::Absolutepath]                      $ldap_tls_cacert_dir     = undef,
  Optional[String]                                    $ldap_tls_ciphers        = undef,
  Optional[Stdlib::Absolutepath]                      $ldap_tls_cert           = undef,
  Optional[Stdlib::Absolutepath]                      $ldap_tls_key            = undef,
  Optional[Boolean]                                   $ldap_use_sasl           = undef,
  Optional[Integer[2, 3]]                             $ldap_version            = undef,
  # rimap
  Optional[SASL::HostPort]                            $imap_server             = undef,
) inherits sasl::params {

  if ! defined(Class['sasl']) {
    fail('You must include the sasl base class before using the sasl::authd class')
  }

  contain sasl::authd::install
  contain sasl::authd::config
  contain sasl::authd::service

  Class['sasl::authd::install'] -> Class['sasl::authd::config']
    ~> Class['sasl::authd::service']
}
