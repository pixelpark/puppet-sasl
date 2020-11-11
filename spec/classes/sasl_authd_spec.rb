require 'spec_helper'

shared_examples_for 'sasl::authd' do
  it { is_expected.to contain_class('sasl::authd') }
  it { is_expected.to contain_class('sasl::authd::config') }
  it { is_expected.to contain_class('sasl::authd::install') }
  it { is_expected.to contain_class('sasl::authd::service') }
  it { is_expected.to contain_service('saslauthd') }
end

describe 'sasl::authd' do
  context 'on unsupported distributions' do
    let(:facts) do
      {
        os: {
          family: 'Unsupported',
        },
      }
    end

    it { is_expected.to compile.and_raise_error(%r{not supported on an Unsupported}) }
  end

  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end

      let(:pre_condition) do
        'include ::sasl'
      end

      [5, 10].each do |threads|
        context "with #{threads} threads" do
          let(:params) do
            {
              threads: threads,
            }
          end

          context 'with pam mechanism', :compile do
            let(:params) do
              super().merge(
                mechanism: 'pam',
              )
            end

            it_behaves_like 'sasl::authd'

            it { is_expected.to contain_file('/etc/saslauthd.conf').with_ensure('absent') }

            case facts[:osfamily]
            when 'Debian'
              it do
                is_expected.to contain_file('/etc/default/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                  # !!! Managed by Puppet !!!

                  START=yes
                  DESC="SASL Authentication Daemon"
                  NAME="saslauthd"
                  MECHANISMS="pam"
                  MECH_OPTIONS=""
                  THREADS=#{threads}
                  OPTIONS="-c -m /var/run/saslauthd"
                EOS
              end
              it { is_expected.to contain_package('sasl2-bin') }
            when 'RedHat'
              socketdir = case facts[:operatingsystemmajrelease]
                          when '6'
                            '/var/run/saslauthd'
                          else
                            '/run/saslauthd'
                          end

              case threads
              when 5
                it do
                  is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                    # !!! Managed by Puppet !!!

                    SOCKETDIR="#{socketdir}"
                    MECH="pam"
                    FLAGS=""
                  EOS
                end
              else
                it do
                  is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                    # !!! Managed by Puppet !!!

                    SOCKETDIR="#{socketdir}"
                    MECH="pam"
                    FLAGS="-n #{threads}"
                  EOS
                end
              end

              it { is_expected.to contain_package('cyrus-sasl') }
            end
          end

          context 'with ldap mechanism' do
            let(:params) do
              super().merge(
                mechanism: 'ldap',
              )
            end

            context 'with default parameters', :compile do
              it_behaves_like 'sasl::authd'

              it do
                is_expected.to contain_file('/etc/saslauthd.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                  # !!! Managed by Puppet !!!

                EOS
              end

              case facts[:osfamily]
              when 'Debian'
                it do
                  is_expected.to contain_file('/etc/default/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                    # !!! Managed by Puppet !!!

                    START=yes
                    DESC="SASL Authentication Daemon"
                    NAME="saslauthd"
                    MECHANISMS="ldap"
                    MECH_OPTIONS=""
                    THREADS=#{threads}
                    OPTIONS="-c -m /var/run/saslauthd"
                  EOS
                end
                it { is_expected.to contain_package('sasl2-bin') }
              when 'RedHat'
                socketdir = case facts[:operatingsystemmajrelease]
                            when '6'
                              '/var/run/saslauthd'
                            else
                              '/run/saslauthd'
                            end

                case threads
                when 5
                  it do
                    is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                      # !!! Managed by Puppet !!!

                      SOCKETDIR="#{socketdir}"
                      MECH="ldap"
                      FLAGS=""
                    EOS
                  end
                else
                  it do
                    is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                      # !!! Managed by Puppet !!!

                      SOCKETDIR="#{socketdir}"
                      MECH="ldap"
                      FLAGS="-n #{threads}"
                    EOS
                  end
                end

                it { is_expected.to contain_package('cyrus-sasl') }
              end
            end

            context 'with alternate configuration file and specified parameters', :compile do
              let(:params) do
                super().merge(
                  ldap_conf_file: '/tmp/saslauthd.conf',
                  # TODO
                )
              end

              it_behaves_like 'sasl::authd'

              it { is_expected.not_to contain_file('/etc/saslauthd.conf') }
              it do
                is_expected.to contain_file('/tmp/saslauthd.conf').with_content(<<-EOS.gsub(%r{^ +}, ''))
                  # !!! Managed by Puppet !!!

                EOS
              end

              case facts[:osfamily]
              when 'Debian'
                it do
                  is_expected.to contain_file('/etc/default/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                    # !!! Managed by Puppet !!!

                    START=yes
                    DESC="SASL Authentication Daemon"
                    NAME="saslauthd"
                    MECHANISMS="ldap"
                    MECH_OPTIONS="/tmp/saslauthd.conf"
                    THREADS=#{threads}
                    OPTIONS="-c -m /var/run/saslauthd"
                  EOS
                end
                it { is_expected.to contain_package('sasl2-bin') }
              when 'RedHat'
                socketdir = case facts[:operatingsystemmajrelease]
                            when '6'
                              '/var/run/saslauthd'
                            else
                              '/run/saslauthd'
                            end

                case threads
                when 5
                  it do
                    is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                      # !!! Managed by Puppet !!!

                      SOCKETDIR="#{socketdir}"
                      MECH="ldap"
                      FLAGS="-O /tmp/saslauthd.conf"
                    EOS
                  end
                else
                  it do
                    is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                      # !!! Managed by Puppet !!!

                      SOCKETDIR="#{socketdir}"
                      MECH="ldap"
                      FLAGS="-O /tmp/saslauthd.conf -n #{threads}"
                    EOS
                  end
                end

                it { is_expected.to contain_package('cyrus-sasl') }
              end
            end
          end

          context 'with rimap method' do
            let(:params) do
              super().merge(
                mechanism: 'rimap',
              )
            end

            context 'with just a hostname', :compile do
              let(:params) do
                super().merge(
                  imap_server: 'imap.example.com',
                )
              end

              it_behaves_like 'sasl::authd'

              it { is_expected.to contain_file('/etc/saslauthd.conf').with_ensure('absent') }

              case facts[:osfamily]
              when 'Debian'
                it do
                  is_expected.to contain_file('/etc/default/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                    # !!! Managed by Puppet !!!

                    START=yes
                    DESC="SASL Authentication Daemon"
                    NAME="saslauthd"
                    MECHANISMS="rimap"
                    MECH_OPTIONS="imap.example.com"
                    THREADS=#{threads}
                    OPTIONS="-c -m /var/run/saslauthd"
                  EOS
                end
                it { is_expected.to contain_package('sasl2-bin') }
              when 'RedHat'
                socketdir = case facts[:operatingsystemmajrelease]
                            when '6'
                              '/var/run/saslauthd'
                            else
                              '/run/saslauthd'
                            end

                case threads
                when 5
                  it do
                    is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                      # !!! Managed by Puppet !!!

                      SOCKETDIR="#{socketdir}"
                      MECH="rimap"
                      FLAGS="-O imap.example.com"
                    EOS
                  end
                else
                  it do
                    is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                      # !!! Managed by Puppet !!!

                      SOCKETDIR="#{socketdir}"
                      MECH="rimap"
                      FLAGS="-O imap.example.com -n #{threads}"
                    EOS
                  end
                end

                it { is_expected.to contain_package('cyrus-sasl') }
              end
            end

            context 'with a hostname and port', :compile do
              let(:params) do
                super().merge(
                  imap_server: ['imap.example.com', 993],
                )
              end

              it_behaves_like 'sasl::authd'

              it { is_expected.to contain_file('/etc/saslauthd.conf').with_ensure('absent') }

              case facts[:osfamily]
              when 'Debian'
                it do
                  is_expected.to contain_file('/etc/default/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                    # !!! Managed by Puppet !!!

                    START=yes
                    DESC="SASL Authentication Daemon"
                    NAME="saslauthd"
                    MECHANISMS="rimap"
                    MECH_OPTIONS="imap.example.com/993"
                    THREADS=#{threads}
                    OPTIONS="-c -m /var/run/saslauthd"
                  EOS
                end
                it { is_expected.to contain_package('sasl2-bin') }
              when 'RedHat'
                socketdir = case facts[:operatingsystemmajrelease]
                            when '6'
                              '/var/run/saslauthd'
                            else
                              '/run/saslauthd'
                            end

                case threads
                when 5
                  it do
                    is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                      # !!! Managed by Puppet !!!

                      SOCKETDIR="#{socketdir}"
                      MECH="rimap"
                      FLAGS="-O imap.example.com/993"
                    EOS
                  end
                else
                  it do
                    is_expected.to contain_file('/etc/sysconfig/saslauthd').with_content(<<-EOS.gsub(%r{^ +}, ''))
                      # !!! Managed by Puppet !!!

                      SOCKETDIR="#{socketdir}"
                      MECH="rimap"
                      FLAGS="-O imap.example.com/993 -n #{threads}"
                    EOS
                  end
                end

                it { is_expected.to contain_package('cyrus-sasl') }
              end
            end
          end
        end
      end
    end
  end
end
