# Installs per-application SASL authentication configuration.
#
# @example Configure Postfix for `DIGEST-MD5` and `CRAM-MD5` authentication using the sasldb backend
#   include ::sasl
#   ::sasl::application { 'smtpd':
#     pwcheck_method => 'auxprop',
#     auxprop_plugin => 'sasldb',
#     mech_list      => ['digest-md5', 'cram-md5'],
#   }
#
# @example Configure Postfix for `PLAIN` and `LOGIN` authentication using the saslauthd backend which itself is using LDAP+STARTTLS
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
#   ::sasl::application { 'smtpd':
#     pwcheck_method => 'saslauthd',
#     mech_list      => ['plain', 'login'],
#   }
#
# @param pwcheck_method The password check method.
# @param mech_list The authentication mechanisms to offer/support.
# @param application The name of the application.
# @param auxprop_plugin If the `pwcheck_method` is `auxprop` then the name of
#   the plugin to use.
# @param ldapdb_uri List of LDAP URI's to query.
# @param ldapdb_id SASL ID to use to authenticate with LDAP.
# @param ldapdb_mech SASL mechanism to use with LDAP.
# @param ldapdb_pw Password to use with LDAP.
# @param ldapdb_rc Path to separate LDAP configuration file.
# @param ldapdb_starttls Whether to attempt STARTTLS or not.
# @param sasldb_path Path to local SASL database.
# @param sql_engine Which SQL engine to use.
# @param sql_hostnames List of database servers to use.
# @param sql_user Database user to use.
# @param sql_passwd Password of database user.
# @param sql_database Name of the database.
# @param sql_select SQL query used with `SELECT` operations.
# @param sql_insert SQL statement used with `INSERT` operations.
# @param sql_update SQL statement used with `UPDATE` operations.
# @param sql_usessl Whether to use SSL or not.
#
# @see puppet_classes::sasl ::sasl
# @see puppet_classes::sasl::authd ::sasl::authd
define sasl::application (
  Enum['auxprop', 'saslauthd']                     $pwcheck_method,
  Array[SASL::Mech, 1]                             $mech_list,
  String                                           $application     = $title,
  Optional[SASL::Auxprop]                          $auxprop_plugin  = undef,
  # ldapdb
  Optional[Array[Bodgitlib::LDAP::URI::Simple, 1]] $ldapdb_uri      = undef,
  Optional[String]                                 $ldapdb_id       = undef,
  Optional[String]                                 $ldapdb_mech     = undef,
  Optional[String]                                 $ldapdb_pw       = undef,
  Optional[Stdlib::Absolutepath]                   $ldapdb_rc       = undef,
  Optional[Enum['try', 'demand']]                  $ldapdb_starttls = undef,
  # sasldb
  Optional[Stdlib::Absolutepath]                   $sasldb_path     = undef,
  # sql
  Optional[Enum['mysql', 'pgsql', 'sqlite']]       $sql_engine      = undef,
  Optional[Array[SASL::HostPort, 1]]               $sql_hostnames   = undef,
  Optional[String]                                 $sql_user        = undef,
  Optional[String]                                 $sql_passwd      = undef,
  Optional[String]                                 $sql_database    = undef,
  Optional[String]                                 $sql_select      = undef,
  Optional[String]                                 $sql_insert      = undef,
  Optional[String]                                 $sql_update      = undef,
  Optional[Boolean]                                $sql_usessl      = undef,
) {

  if ! defined(Class['sasl']) {
    fail('You must include the sasl base class before using any sasl defined resources')
  }

  $service_file = "${::sasl::application_directory}/${application}.conf"

  file { $service_file:
    ensure  => file,
    owner   => 0,
    group   => 0,
    mode    => '0644',
    content => template("${module_name}/application.conf.erb"),
  }

  case $pwcheck_method {
    'auxprop': {
      $auxprop_package = $::sasl::auxprop_packages[$auxprop_plugin]
      ensure_packages([$auxprop_package])
      Package[$auxprop_package] -> File[$service_file]
    }
    'saslauthd': {
      # Require saslauthd if that's the method
      if ! defined(Class['sasl::authd']) {
        fail('You must include the sasl::authd class before using any sasl defined resources')
      }
      Class['sasl::authd'] -> File[$service_file]
    }
    default: {
      # noop
    }
  }

  # Build up an array of packages that need to be installed based on the
  # chosen authentication mechanisms
  $packages = unique(values($::sasl::mech_packages.filter |Tuple $package| {
    member($mech_list, $package[0])
  }))
  ensure_packages($packages)
  Package[$packages] -> File[$service_file]
}
