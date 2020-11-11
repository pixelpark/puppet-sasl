require 'spec_helper_acceptance'

describe 'sasl::application' do
  # rubocop:disable ConditionalAssignment
  case fact('osfamily')
  when 'RedHat'
    plain_package_name  = 'cyrus-sasl-plain'
    md5_package_name    = 'cyrus-sasl-md5'
    sasldb_package_name = 'cyrus-sasl-lib'
    application_file    = '/etc/sasl2/test.conf'
  when 'Debian'
    plain_package_name = 'libsasl2-modules'
    md5_package_name   = 'libsasl2-modules'
    application_file   = '/usr/lib/sasl2/test.conf'

    case fact('operatingsystem')
    when 'Ubuntu'
      case fact('operatingsystemrelease')
      when '14.04'
        sasldb_package_name = 'libsasl2-modules-db'
      else
        sasldb_package_name = 'libsasl2-modules'
      end
    else
      sasldb_package_name = 'libsasl2-modules'
    end
  end
  # rubocop:enable ConditionalAssignment

  context 'with saslauthd method and plain mechanisms' do
    it 'works with no errors' do
      pp = <<-EOS
        include ::sasl
        class { '::sasl::authd':
          mechanism => pam,
        }
        ::sasl::application { 'test':
          pwcheck_method => saslauthd,
          mech_list      => ['plain', 'login'],
        }
      EOS

      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes:  true)
    end

    describe file(application_file) do
      it { is_expected.to be_file }
      its(:content) do
        is_expected.to eq <<-EOS.gsub(%r{^ +}, '')
          pwcheck_method: saslauthd
          mech_list: plain login
        EOS
      end
    end

    describe package(plain_package_name) do
      it { is_expected.to be_installed }
    end
  end

  context 'with sasldb method and md5 mechanisms' do
    it 'works with no errors' do
      pp = <<-EOS
        include ::sasl
        ::sasl::application { 'test':
          pwcheck_method => auxprop,
          auxprop_plugin => sasldb,
          mech_list      => ['digest-md5', 'cram-md5'],
        }
      EOS

      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes:  true)
    end

    describe file(application_file) do
      it { is_expected.to be_file }
      its(:content) do
        is_expected.to eq <<-EOS.gsub(%r{^ +}, '')
          pwcheck_method: auxprop
          mech_list: digest-md5 cram-md5
          auxprop_plugin: sasldb
        EOS
      end
    end

    describe package(md5_package_name) do
      it { is_expected.to be_installed }
    end

    describe package(sasldb_package_name) do
      it { is_expected.to be_installed }
    end
  end
end
