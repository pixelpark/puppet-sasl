# @since 2.0.0
type SASL::HostPort = Variant[Variant[Bodgitlib::Hostname, Stdlib::IP::Address::V4::NoSubnet], Tuple[Variant[Bodgitlib::Hostname, Stdlib::IP::Address::V4::NoSubnet], Bodgitlib::Port]]
