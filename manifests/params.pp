# @!visibility private
class sasl::params {

  $saslauthd_hasstatus      = true
  $saslauthd_service        = 'saslauthd'
  $saslauthd_ldap_conf_file = '/etc/saslauthd.conf'
  $saslauthd_threads        = 5
  $saslauthd_caching        = false
  $saslauthd_combine_realm  = false

  case $facts['os']['family'] {
    'RedHat': {
      $package_name          = 'cyrus-sasl-lib'
      $application_directory = '/etc/sasl2'
      $auxprop_packages      = {
        'ldapdb' => 'cyrus-sasl-ldap',
        'sasldb' => 'cyrus-sasl-lib',
        'sql'    => 'cyrus-sasl-sql',
      }
      $sasldb_package        = 'cyrus-sasl-lib'
      $mech_packages         = {
        'anonymous'  => 'cyrus-sasl-lib',
        'cram-md5'   => 'cyrus-sasl-md5',
        'digest-md5' => 'cyrus-sasl-md5',
        'login'      => 'cyrus-sasl-plain',
        'ntlm'       => 'cyris-sasl-ntlm',
        'plain'      => 'cyrus-sasl-plain',
      }
      $saslauthd_package     = 'cyrus-sasl'
      $saslauthd_socket      = $facts['os']['release']['major'] ? {
        '6'     => '/var/run/saslauthd',
        default => '/run/saslauthd',
      }
    }
    'Debian': {
      $package_name          = 'libsasl2-2'
      $application_directory = '/usr/lib/sasl2'
      $sasldb_package        = 'sasl2-bin'
      $mech_packages         = {
        'anonymous'  => 'libsasl2-modules',
        'cram-md5'   => 'libsasl2-modules',
        'digest-md5' => 'libsasl2-modules',
        'login'      => 'libsasl2-modules',
        'ntlm'       => 'libsasl2-modules',
        'plain'      => 'libsasl2-modules',
      }
      $saslauthd_package     = 'sasl2-bin'
      $saslauthd_socket      = '/var/run/saslauthd'

      case $facts['os']['name'] {
        'Ubuntu': {
          case $facts['os']['release']['full'] {
            '14.04': {
              $auxprop_packages = {
                'ldapdb' => 'libsasl2-modules-ldap',
                'sasldb' => 'libsasl2-modules-db',
                'sql'    => 'libsasl2-modules-sql',
              }
            }
            default: {
              $auxprop_packages = {
                'ldapdb' => 'libsasl2-modules-ldap',
                'sasldb' => 'libsasl2-modules',
                'sql'    => 'libsasl2-modules-sql',
              }
            }
          }
        }
        default: {
          $auxprop_packages = {
            'ldapdb' => 'libsasl2-modules-ldap',
            'sasldb' => 'libsasl2-modules',
            'sql'    => 'libsasl2-modules-sql',
          }
        }
      }
    }
    default: {
      fail("The ${module_name} module is not supported on an ${facts['os']['family']} based system.")
    }
  }
}
