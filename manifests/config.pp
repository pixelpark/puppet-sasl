# @!visibility private
class sasl::config {

  $application_directory = $::sasl::application_directory

  file { $application_directory:
    ensure  => directory,
    owner   => 0,
    group   => 0,
    mode    => '0644',
    purge   => true,
    recurse => true,
  }

  # Debian/Ubuntu drop two files in the application directory to help with
  # migrating `sasldb` between versions of BerkeleyDB so stop them from being
  # purged away
  if $facts['os']['family'] == 'Debian' {
    file { "${application_directory}/berkeley_db.active":
      ensure => file,
      owner  => 0,
      group  => 0,
      mode   => '0644',
    }

    file { "${application_directory}/berkeley_db.txt":
      ensure => file,
      owner  => 0,
      group  => 0,
      mode   => '0644',
    }
  }
}
