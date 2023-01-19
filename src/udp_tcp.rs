pub mod UDP_TCP {

    // TCP
    const HTTP  : u16 = 80;
    const HTTPS : u16 = 443;

    // UDP
    const DHCP_1  : u16 = 67;
    const DHCP_2  : u16 = 68;

    // MIX
    const DNS     : u16 = 53;

    #[derive(PartialEq, PartialOrd)]
    pub enum Port {

        HTTP(u16),
        HTTPS(u16),
        DHCP_1(u16),
        DHCP_2(u16),
        DNS(u16),
        UNKNOWN(u16),

    }
    impl From<u16> for Port {
        fn from(value: u16) -> Self {
            if value == HTTP {
                return Self::HTTP(value);
            }
            if value == HTTPS {
                return Self::HTTPS(value);
            }
            if value == DNS {
                return Self::DNS(value);
            }
            if value == DHCP_1 {
                return Self::DHCP_1(value);
            }
            if value == DHCP_2 {
                return Self::DHCP_2(value);
            }
            Self::UNKNOWN(value)
        }
    }

}