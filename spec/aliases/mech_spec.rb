require 'spec_helper'

if Puppet.version.to_f >= 4.4
  describe 'test::mech', type: :class do
    describe 'accepts auth mechanisms' do
      [
        'anonymous',
        'cram-md5',
        'digest-md5',
        'login',
        'ntlm',
        'plain',
        'external',
      ].each do |value|
        describe value.inspect do
          let(:params) {{ value: value }}
          it { is_expected.to compile }
        end
      end
    end
    describe 'rejects other values' do
      [
        123,
        'invalid',
      ].each do |value|
        describe value.inspect do
          let(:params) {{ value: value }}
          it { is_expected.to compile.and_raise_error(/parameter 'value' /) }
        end
      end
    end
  end
end
