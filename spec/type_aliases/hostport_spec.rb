require 'spec_helper'

describe 'SASL::HostPort' do
  it { is_expected.to allow_value('127.0.0.1') }
  it { is_expected.to allow_value('host.example.com') }
  it { is_expected.to allow_value(['127.0.0.1', 143]) }
  it { is_expected.to allow_value(['host.example.com', 143]) }
  it { is_expected.not_to allow_value(123) }
  it { is_expected.not_to allow_value(['127.0.0.1', '123']) }
  it { is_expected.not_to allow_value('256.0.0.1') }
  it { is_expected.not_to allow_value(['127.0.0.1', 65_536]) }
end
