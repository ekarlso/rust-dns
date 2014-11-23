use std::str::FromStr;

use types::raw::FromRaw;

pub enum Class {
    INET = 1,
    CSNET = 2,
    CHAOS = 3,
    HESIOD = 4,
    NONE = 254,
    ANY = 255
}

impl FromStr for Class {
    fn from_str(s: &str) -> Option<Class> {
        let i = match s {
            "INET"         => Class::INET,
            "CSNET"        => Class::CSNET,
            "CHAOS"        => Class::CHAOS,
            "HESIOD"       => Class::HESIOD,
            "NONE"         => Class::NONE,
            "ANY"          => Class::ANY,
            _              => panic!("Invalid Type")
        };

        Some(i)
    }
}

impl FromRaw for Class {
    fn from_raw (r: int) -> Class {
        match r {
            1       => Class::INET,
            2       => Class::CSNET,
            3       => Class::CHAOS,
            4       => Class::HESIOD,
            254     => Class::NONE,
            255     => Class::ANY,
            _       => panic!("Invalid Type")
        }
    }
}