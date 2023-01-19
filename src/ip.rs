pub mod IP {

    const TCP   : u8 = 0x06;
    const UDP   : u8 = 0x11;
    const ICMP  : u8 = 0x01;


    #[derive(PartialEq, PartialOrd)]
    pub enum Protocol {

        UDP(u8),
        TCP(u8),
        ICMP(u8),
        UNKNOWN(u8),
    }

    impl From<u8> for Protocol {
        fn from(value: u8) -> Self {
            if value == TCP{
                return Self::TCP(value);
            }
            if value == UDP{
                return Self::UDP(value);
            }
            if value == ICMP {
                return Self::ICMP(value);
            }
            Self::UNKNOWN(value)
        }
    }

}