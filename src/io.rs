use std::io;
use libc;

use types::{Class,Type};
use types::FromRaw;
use std::str::from_str;


macro_rules! unwrap(($e: expr) => (match $e { Ok(v) => v, Err(e) => return Err(e) }))


pub trait DNSReader {
    fn read_dns_name(self) -> io::IoResult<Vec<String>>;
    fn read_dns_type(self) -> io::IoResult<Type>;
    fn read_dns_class(self) -> io::IoResult<Class>;
}


impl<'a> DNSReader for &'a mut io::Reader + 'a {
    fn read_dns_name(self) -> io::IoResult<Vec<String>> {
        let mut name = Vec::new();

        let mut c = true;

        while c {
            let n = self.read_u8().unwrap();

            if n == 0 {
                c = false;
            } else if n < 64{
                let mut part = Vec::new();

                self.push(n as uint, &mut part).unwrap();

                match String::from_utf8(part) {
                    Ok(s) => name.push(s),
                    Err(_) => return Err(io::IoError::from_errno(libc::consts::os::posix88::EILSEQ as uint, false))
                }
            } else {
                // TODO: Actually implement the compression scheme, not sure if it is ever used, but standards!
                return Err(io::IoError::from_errno(libc::consts::os::posix88::EILSEQ as uint, false));
            }
        }

        return Ok(name);
    }

    fn read_dns_type(self) -> io::IoResult<Type> {
        let t: Type = FromRaw::from_raw(self.read_be_u16().unwrap() as int).unwrap();
        Ok(t)
    }

    fn read_dns_class(self) -> io::IoResult<Class> {
        // TODO(ekarlso): This is broke atm.
        Ok(Class::INET)
    }
}


pub trait DNSWriter {
    fn write_dns_name(self, name: &Vec<String>) -> io::IoResult<()>;
    fn write_dns_type(self, ty: &Type) -> io::IoResult<()>;
    fn write_dns_class(self, class: &Class) -> io::IoResult<()>;
}

impl<'a> DNSWriter for &'a mut io::Writer + 'a {
    fn write_dns_name(self, name: &Vec<String>) -> io::IoResult<()> {
        for part in name.iter() {
            let length = part.len();

            if length < 64 {
                unwrap!(self.write_u8(part.len() as u8));
                unwrap!(self.write_str(part.as_slice()));
            } else {
                return Err(io::IoError::from_errno(libc::consts::os::posix88::EILSEQ as uint, false))
            }
        }

        return self.write_u8(0)
    }

    fn write_dns_type(self, ty: &Type) -> io::IoResult<()> {
        return self.write_be_u16(*ty as u16)
    }

    fn write_dns_class(self, class: &Class) -> io::IoResult<()> {
        return self.write_be_u16(*class as u16)
    }
}