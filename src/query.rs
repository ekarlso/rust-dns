use std::io;
use std::default;

use io::{DNSReader,DNSWriter};
use types::{Class,Type};

macro_rules! unwrap(($e: expr) => (match $e { Ok(v) => v, Err(e) => return Err(e) }))


#[deriving(Show,Default,Clone)]
pub struct Question {
    pub name: Vec<String>,
    pub ty: Type,
    pub class: Class
}

impl Question {
    pub fn from_reader(r: &mut io::Reader) -> io::IoResult<Question> {
        let name = unwrap!(r.read_dns_name());
        let qtype = unwrap!(r.read_dns_type());
        let class = unwrap!(r.read_dns_class());

        return Ok(
            Question {
                name: name,
                ty: qtype,
                class: class
            }
        );
    }

    pub fn write_to(&self, w: &mut io::Writer) -> io::IoResult<()> {
        unwrap!(w.write_dns_name(&self.name));
        unwrap!(w.write_dns_type(&self.ty));

        return w.write_dns_class(&self.class);
    }
}


#[repr(u16)]
#[deriving(Show,PartialEq)]
pub enum QueryResponse {
    QUERY = 0,
    RESPONSE = 1
}


impl default::Default for QueryResponse {
    fn default() -> QueryResponse { QueryResponse::QUERY }
}


#[cfg(test)]
mod test {
    use types::{Class,Type};

    use query::Question;

    #[test]
    fn test_simple() {
        let name = Vec::new();

        let q = Question {
            name: name,
            ty: Type::A,
            class: Class::INET
        };
    }
}


