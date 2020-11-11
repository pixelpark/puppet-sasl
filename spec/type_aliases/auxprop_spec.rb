require 'spec_helper'

describe 'SASL::Auxprop' do
  it { is_expected.to allow_value('ldapdb') }
  it { is_expected.to allow_value('sasldb') }
  it { is_expected.to allow_value('sql') }
  it { is_expected.not_to allow_value(123) }
  it { is_expected.not_to allow_value('invalid') }
end
