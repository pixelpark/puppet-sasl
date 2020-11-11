require 'spec_helper'

describe 'SASL::Mech' do
  it { is_expected.to allow_value('anonymous') }
  it { is_expected.to allow_value('cram-md5') }
  it { is_expected.to allow_value('digest-md5') }
  it { is_expected.to allow_value('login') }
  it { is_expected.to allow_value('ntlm') }
  it { is_expected.to allow_value('plain') }
  it { is_expected.to allow_value('external') }
  it { is_expected.not_to allow_value(123) }
  it { is_expected.not_to allow_value('invalid') }
end
