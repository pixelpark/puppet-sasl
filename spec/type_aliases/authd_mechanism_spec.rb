require 'spec_helper'

describe 'SASL::Authd::Mechanism' do
  it { is_expected.to allow_value('getpwent') }
  it { is_expected.to allow_value('httpform') }
  it { is_expected.to allow_value('kerberos5') }
  it { is_expected.to allow_value('ldap') }
  it { is_expected.to allow_value('pam') }
  it { is_expected.to allow_value('rimap') }
  it { is_expected.to allow_value('sasldb') }
  it { is_expected.to allow_value('shadow') }
  it { is_expected.not_to allow_value(123) }
  it { is_expected.not_to allow_value('invalid') }
end
