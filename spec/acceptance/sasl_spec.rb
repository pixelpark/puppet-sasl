require 'spec_helper_acceptance'

describe 'sasl' do
  case fact('osfamily')
  when 'RedHat'
    package_name          = 'cyrus-sasl-lib'
    application_directory = '/etc/sasl2'
  when 'Debian'
    package_name          = 'libsasl2-2'
    application_directory = '/usr/lib/sasl2'
  end

  it 'works with no errors' do
    pp = <<-EOS
      include ::sasl
    EOS

    apply_manifest(pp, catch_failures: true)
    apply_manifest(pp, catch_changes: true)
  end

  describe file(application_directory) do
    it { is_expected.to be_directory }
  end

  describe package(package_name) do
    it { is_expected.to be_installed }
  end
end
