require 'spec_helper_acceptance'

describe 'sasl::authd' do
  # rubocop:disable ConditionalAssignment
  case fact('osfamily')
  when 'RedHat'
    package_name = 'cyrus-sasl'
    pam_service  = 'system-auth'
    case fact('operatingsystemmajrelease')
    when '6'
      socket = '/var/run/saslauthd'
    else
      socket = '/run/saslauthd'
    end
  when 'Debian'
    package_name = 'sasl2-bin'
    pam_service  = 'common-auth'
  end
  # rubocop:enable ConditionalAssignment

  context 'with pam mechanism' do
    it 'works with no errors' do
      pp = <<-EOS
        group { 'test':
          ensure => present,
          gid    => 2000,
        }
        user { 'test':
          ensure     => present,
          comment    => 'Test user',
          gid        => 2000,
          managehome => true,
          # test
          password   => '$6$VWLrFvt.$NvABeDqNvdlTagbYRZADaSEzA9w1/Ny7XtDneE2EZZ8GVMdY9FLMUQMfTVUJEE8cbNt8.3RGBjjoGBj1sFzbX0',
          shell      => '/bin/bash',
          uid        => 2000,
          require    => Group['test'],
        }
        include ::sasl
        class { '::sasl::authd':
          mechanism => pam,
          threads   => 1,
        }
      EOS

      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes:  true)
    end

    describe package(package_name) do
      it { is_expected.to be_installed }
    end

    describe file('/etc/sysconfig/saslauthd'), if: fact('osfamily').eql?('RedHat') do
      it { is_expected.to be_file }
      it { is_expected.to be_mode 644 }
      it { is_expected.to be_owned_by 'root' }
      it { is_expected.to be_grouped_into 'root' }
      its(:content) do
        is_expected.to eq <<-EOS.gsub(%r{^ +}, '')
          # !!! Managed by Puppet !!!

          SOCKETDIR="#{socket}"
          MECH="pam"
          FLAGS="-n 1"
        EOS
      end
    end

    describe file('/etc/default/saslauthd'), if: fact('osfamily').eql?('Debian') do
      it { is_expected.to be_file }
      it { is_expected.to be_mode 644 }
      it { is_expected.to be_owned_by 'root' }
      it { is_expected.to be_grouped_into 'root' }
      its(:content) do
        is_expected.to eq <<-EOS.gsub(%r{^ +}, '')
          # !!! Managed by Puppet !!!

          START=yes
          DESC="SASL Authentication Daemon"
          NAME="saslauthd"
          MECHANISMS="pam"
          MECH_OPTIONS=""
          THREADS=1
          OPTIONS="-c -m /var/run/saslauthd"
        EOS
      end
    end

    # Debian Squeeze doesn't support 'service saslauthd status'
    describe service('saslauthd'), unless: fact('operatingsystem').eql?('Debian') && fact('operatingsystemmajrelease').eql?('6') do
      it { is_expected.to be_enabled }
      it { is_expected.to be_running }
    end

    describe service('saslauthd'), if: fact('operatingsystem').eql?('Debian') && fact('operatingsystemmajrelease').eql?('6') do
      it { is_expected.to be_enabled }
    end

    describe process('saslauthd'), if: fact('operatingsystem').eql?('Debian') && fact('operatingsystemmajrelease').eql?('6') do
      it { is_expected.to be_running }
    end

    describe command("testsaslauthd -u test -p test -s #{pam_service}") do
      its(:stdout) { is_expected.to match %r{^0: OK "Success."} }
      its(:exit_status) { is_expected.to eq 0 }
    end

    # describe command("testsaslauthd -u test -p invalid -s #{pam_service}") do
    #   its(:stdout) { is_expected.to match /^0: NO "authentication failed"/ }
    #   its(:exit_status) { is_expected.to eq 255 }
    # end
  end

  context 'with ldap mechanism' do
    it 'works with no errors' do
      pp = <<-EOS
        include ::openldap
        include ::openldap::client
        class { '::openldap::server':
          root_dn       => 'cn=Manager,dc=example,dc=com',
          root_password => 'secret',
          suffix        => 'dc=example,dc=com',
          access        => [
            [
              {
                'attrs' => ['userPassword'],
              },
              [
                {
                  'who'    => ['self'],
                  'access' => '=xw',
                },
                {
                  'who'    => ['anonymous'],
                  'access' => 'auth',
                },
              ],
            ],
            [
              {
                'dn' => '*',
              },
              [
                {
                  'who'    => ['dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"'],
                  'access' => 'manage',
                },
                {
                  'who'    => ['users'],
                  'access' => 'read',
                },
              ],
            ],
          ],
          interfaces    => ['ldap://#{default.ip}/'],
          local_ssf     => 256,
        }
        ::openldap::server::schema { 'cosine':
          ensure => present,
        }
        ::openldap::server::schema { 'inetorgperson':
          ensure => present,
        }
        ::openldap::server::schema { 'nis':
          ensure  => present,
          require => ::Openldap::Server::Schema['cosine'],
        }

        include ::sasl
        class { '::sasl::authd':
          mechanism        => ldap,
          threads          => 1,
          ldap_auth_method => 'bind',
          ldap_bind_dn     => 'cn=Manager,dc=example,dc=com',
          ldap_bind_pw     => 'secret',
          ldap_search_base => 'dc=example,dc=com',
          ldap_servers     => ['ldap://#{default.ip}'],
          ldap_start_tls   => false,
          require          => Class['::openldap::server'],
        }
      EOS

      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes:  true)
    end

    describe command('ldapadd -Y EXTERNAL -H ldapi:/// -f /root/example.ldif') do
      its(:exit_status) { is_expected.to eq 0 }
    end

    describe package(package_name) do
      it { is_expected.to be_installed }
    end

    describe file('/etc/sysconfig/saslauthd'), if: fact('osfamily').eql?('RedHat') do
      it { is_expected.to be_file }
      it { is_expected.to be_mode 644 }
      it { is_expected.to be_owned_by 'root' }
      it { is_expected.to be_grouped_into 'root' }
      its(:content) do
        is_expected.to eq <<-EOS.gsub(%r{^ +}, '')
          # !!! Managed by Puppet !!!

          SOCKETDIR="#{socket}"
          MECH="ldap"
          FLAGS="-n 1"
        EOS
      end
    end

    describe file('/etc/default/saslauthd'), if: fact('osfamily').eql?('Debian') do
      it { is_expected.to be_file }
      it { is_expected.to be_mode 644 }
      it { is_expected.to be_owned_by 'root' }
      it { is_expected.to be_grouped_into 'root' }
      its(:content) do
        is_expected.to eq <<-EOS.gsub(%r{^ +}, '')
          # !!! Managed by Puppet !!!

          START=yes
          DESC="SASL Authentication Daemon"
          NAME="saslauthd"
          MECHANISMS="ldap"
          MECH_OPTIONS=""
          THREADS=1
          OPTIONS="-c -m /var/run/saslauthd"
        EOS
      end
    end

    describe file('/etc/saslauthd.conf') do
      it { is_expected.to be_file }
      it { is_expected.to be_mode 644 }
      it { is_expected.to be_owned_by 'root' }
      it { is_expected.to be_grouped_into 'root' }
      its(:content) do
        is_expected.to eq <<-EOS.gsub(%r{^ +}, '')
          # !!! Managed by Puppet !!!

          ldap_auth_method: bind
          ldap_bind_dn: cn=Manager,dc=example,dc=com
          ldap_bind_pw: secret
          ldap_search_base: dc=example,dc=com
          ldap_servers: ldap://#{default.ip}
          ldap_start_tls: no
        EOS
      end
    end

    # Debian Squeeze doesn't support 'service saslauthd status'
    describe service('saslauthd'), unless: fact('operatingsystem').eql?('Debian') && fact('operatingsystemmajrelease').eql?('6') do
      it { is_expected.to be_enabled }
      it { is_expected.to be_running }
    end

    describe service('saslauthd'), if: fact('operatingsystem').eql?('Debian') && fact('operatingsystemmajrelease').eql?('6') do
      it { is_expected.to be_enabled }
    end

    describe process('saslauthd'), if: fact('operatingsystem').eql?('Debian') && fact('operatingsystemmajrelease').eql?('6') do
      it { is_expected.to be_running }
    end

    describe command('testsaslauthd -u alice -p password') do
      its(:stdout) { is_expected.to match %r{^0: OK "Success."} }
      its(:exit_status) { is_expected.to eq 0 }
    end
  end
end
