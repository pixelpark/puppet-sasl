require 'spec_helper'

describe 'sasl::application' do
  let(:title) do
    'test'
  end

  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end

      context 'without sasl class included' do
        let(:params) do
          {
            pwcheck_method: 'auxprop',
            auxprop_plugin: 'sasldb',
            mech_list:      ['plain', 'login'],
          }
        end

        it { is_expected.to compile.and_raise_error(%r{must include the sasl base class}) }
      end

      context 'with sasl class included' do
        let(:pre_condition) do
          'include ::sasl'
        end

        context 'with sasldb method' do
          let(:params) do
            {
              pwcheck_method: 'auxprop',
              auxprop_plugin: 'sasldb',
              mech_list:      ['plain', 'login'],
            }
          end

          it { is_expected.to compile.with_all_deps }

          case facts[:osfamily]
          when 'Debian'
            it do
              is_expected.to contain_file('/usr/lib/sasl2/test.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                pwcheck_method: auxprop
                mech_list: plain login
                auxprop_plugin: sasldb
              EOS
            end
            it { is_expected.to contain_package('libsasl2-modules') }

            case facts[:operatingsystem]
            when 'Ubuntu'
              case facts[:operatingsystemrelease]
              when '14.04'
                it { is_expected.to contain_package('libsasl2-modules-db') }
              end
            end
          when 'RedHat'
            it do
              is_expected.to contain_file('/etc/sasl2/test.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                pwcheck_method: auxprop
                mech_list: plain login
                auxprop_plugin: sasldb
              EOS
            end
            it { is_expected.to contain_package('cyrus-sasl-plain') }
          end

          it { is_expected.to contain_sasl__application('test') }
        end

        context 'with ldapdb method' do
          let(:params) do
            {
              pwcheck_method: 'auxprop',
              auxprop_plugin: 'ldapdb',
              mech_list:      ['plain', 'login'],
              ldapdb_uri:     ['ldap://example.com', 'ldaps://example.com'],
            }
          end

          case facts[:osfamily]
          when 'Debian'
            it do
              is_expected.to contain_file('/usr/lib/sasl2/test.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                pwcheck_method: auxprop
                mech_list: plain login
                auxprop_plugin: ldapdb
                ldapdb_uri: ldap://example.com ldaps://example.com
              EOS
            end
            it { is_expected.to contain_package('libsasl2-modules') }
            it { is_expected.to contain_package('libsasl2-modules-ldap') }
          when 'RedHat'
            it do
              is_expected.to contain_file('/etc/sasl2/test.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                pwcheck_method: auxprop
                mech_list: plain login
                auxprop_plugin: ldapdb
                ldapdb_uri: ldap://example.com ldaps://example.com
              EOS
            end
            it { is_expected.to contain_package('cyrus-sasl-ldap') }
            it { is_expected.to contain_package('cyrus-sasl-plain') }
          end

          it { is_expected.to contain_sasl__application('test') }
        end

        context 'with sql method' do
          let(:params) do
            {
              pwcheck_method: 'auxprop',
              auxprop_plugin: 'sql',
              mech_list:      ['plain', 'login'],
              sql_engine:     'mysql',
              sql_hostnames:  ['localhost', ['127.0.0.1', 3306]],
            }
          end

          case facts[:osfamily]
          when 'Debian'
            it do
              is_expected.to contain_file('/usr/lib/sasl2/test.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                pwcheck_method: auxprop
                mech_list: plain login
                auxprop_plugin: sql
                sql_engine: mysql
                sql_hostnames: localhost, 127.0.0.1:3306
              EOS
            end
            it { is_expected.to contain_package('libsasl2-modules') }
            it { is_expected.to contain_package('libsasl2-modules-sql') }
          when 'RedHat'
            it do
              is_expected.to contain_file('/etc/sasl2/test.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                pwcheck_method: auxprop
                mech_list: plain login
                auxprop_plugin: sql
                sql_engine: mysql
                sql_hostnames: localhost, 127.0.0.1:3306
              EOS
            end
            it { is_expected.to contain_package('cyrus-sasl-plain') }
            it { is_expected.to contain_package('cyrus-sasl-sql') }
          end

          it { is_expected.to contain_sasl__application('test') }
        end

        context 'with saslauthd method' do
          let(:params) do
            {
              pwcheck_method: 'saslauthd',
              mech_list:      ['plain', 'login'],
            }
          end

          context 'without sasl::authd class included' do
            it { expect { is_expected.to compile }.to raise_error(%r{must include the sasl::authd class}) }
          end

          context 'with sasl::authd class included' do
            let(:pre_condition) do
              'include ::sasl class { "::sasl::authd": mechanism => pam }'
            end

            it { is_expected.to compile.with_all_deps }

            case facts[:osfamily]
            when 'Debian'
              it do
                is_expected.to contain_file('/usr/lib/sasl2/test.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                  pwcheck_method: saslauthd
                  mech_list: plain login
                EOS
              end
              it { is_expected.to contain_package('libsasl2-modules') }
            when 'RedHat'
              it do
                is_expected.to contain_file('/etc/sasl2/test.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                  pwcheck_method: saslauthd
                  mech_list: plain login
                EOS
              end
              it { is_expected.to contain_package('cyrus-sasl-plain') }
            end

            it { is_expected.to contain_sasl__application('test') }
          end
        end
      end
    end
  end
end
