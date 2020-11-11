# Installs and manages Cyrus SASL.
#
# @example Declaring the class
#   include ::sasl
#
# @param application_directory Per-application configuration directory, usually
#   `/etc/sasl2` or `/usr/lib/sasl2`.
# @param package_name The name of the core package.
# @param auxprop_packages Hash of Auxiliary Property plugins mapped to the
#   package that provides them.
# @param mech_packages Hash of authentication mechanisms mapped to the package
#   that provides them.
#
# @see puppet_classes::sasl::authd ::sasl::authd
# @see puppet_defined_types::sasl::application ::sasl::application
class sasl (
  Stdlib::Absolutepath        $application_directory = $::sasl::params::application_directory,
  String                      $package_name          = $::sasl::params::package_name,
  Hash[SASL::Auxprop, String] $auxprop_packages      = $::sasl::params::auxprop_packages,
  Hash[SASL::Mech, String]    $mech_packages         = $::sasl::params::mech_packages,
) inherits sasl::params {

  contain sasl::install
  contain sasl::config

  Class['sasl::install'] -> Class['sasl::config']
}
