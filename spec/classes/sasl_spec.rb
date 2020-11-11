require 'spec_helper'

describe 'sasl' do
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

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_class('sasl') }
      it { is_expected.to contain_class('sasl::config') }
      it { is_expected.to contain_class('sasl::install') }
      it { is_expected.to contain_class('sasl::params') }

      case facts[:osfamily]
      when 'Debian'
        it { is_expected.to contain_file('/usr/lib/sasl2') }
        it { is_expected.to contain_file('/usr/lib/sasl2/berkeley_db.active') }
        it { is_expected.to contain_file('/usr/lib/sasl2/berkeley_db.txt') }
        it { is_expected.to contain_package('libsasl2-2') }
      when 'RedHat'
        it { is_expected.to contain_file('/etc/sasl2') }
        it { is_expected.to contain_package('cyrus-sasl-lib') }
      end
    end
  end
end
