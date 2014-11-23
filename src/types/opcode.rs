use std::str::FromStr;

use types::raw::FromRaw;

pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

impl FromStr for Opcode {
    fn from_str(s: &str) -> Option<Opcode> {
        let i = match s {
            "Query"        => Opcode::Query,
            "IQuery"       => Opcode::IQuery,
            "Status"       => Opcode::Status,
            "Notify"       => Opcode::Notify,
            "Update"       => Opcode::Update,
            _              => panic!("Invalid Type")
        };

        Some(i)
    }
}

impl FromRaw for Opcode {
    fn from_raw(r: int) -> Opcode {
        match r {
            0        => Opcode::Query,
            1       => Opcode::IQuery,
            2       => Opcode::Status,
            4       => Opcode::Notify,
            5       => Opcode::Update,
            _              => panic!("Invalid Type")
        }
    }
}