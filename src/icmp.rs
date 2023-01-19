pub mod ICMP {

    const REQUEST   : u8 = 8;
    const REPLY     : u8 = 0;

    #[derive(PartialEq, PartialOrd)]
    pub enum Type {

        REQUEST(u8),
        REPLY(u8),
        UNKNOWN(u8),

    }
    impl From<u8> for Type {
        fn from(value: u8) -> Self {
            if value == REQUEST {
                return Self::REQUEST(value);
            }
            if value == REPLY {
                return Self::REPLY(value);
            }
            Self::UNKNOWN(value)
        }
    }



}