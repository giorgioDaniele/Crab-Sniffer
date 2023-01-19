pub mod ARP {

    const RESERVED: u16 = 0;
    const ETHERNET: u16 = 1;
    const IEE802: u16 = 6;
    const FRAME_RELAY: u16 = 15;

    #[derive(PartialEq, PartialOrd)]
    pub enum HardwareType {
        RESERVED(u16),
        ETHERNET(u16),
        IEE802(u16),
        FRAME_RELAY(u16),
        UNKNOWN(u16),
    }

    impl From<u16> for HardwareType {
        fn from(value: u16) -> Self {
            if value == RESERVED {
                return Self::RESERVED(value);
            }
            if value == ETHERNET {
                return Self::ETHERNET(value);
            }
            if value == IEE802 {
                return Self::IEE802(value);
            }
            if value == FRAME_RELAY {
                return Self::FRAME_RELAY(value);
            }
            Self::UNKNOWN(value)
        }
    }

    const REQUEST : u16 = 1;
    const REPLAY  : u16 = 2;

    #[derive(PartialEq, PartialOrd)]
    pub enum OperationCode {
        REQUEST(u16),
        REPLAY(u16),
        UNKNOWN(u16),
    }
    impl From<u16> for OperationCode {
        fn from(value: u16) -> Self {
            if value == REQUEST {
                return Self::REQUEST(value);
            }
            if value == REPLAY {
                return Self::REPLAY(value);
            }
            Self::UNKNOWN(value)
        }
    }

    

}
