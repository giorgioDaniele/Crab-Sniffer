pub mod ETHERNET {

    const ARP  : u16 = 0x0806;
    const IPV4 : u16 = 0x0800;
    const IPV6 : u16 = 0x86DD;

    #[derive(PartialEq, PartialOrd)]
    pub enum EtherType {

        ARP(u16),
        IPV4(u16),
        IPV6(u16),
        UNKNOWN(u16),
    }

    impl From<u16> for EtherType {
        fn from(value: u16) -> Self {
            if value == ARP {
                return Self::ARP(value);
            }
            if value == IPV4 {
                return Self::IPV4(value);
            }
            if value == IPV6 {
                return Self::IPV6(value);
            }
            Self::UNKNOWN(value)
        }
    }

}