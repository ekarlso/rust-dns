use std::io;
use std::default;
use libc;

use io::{DNSReader,DNSWriter};
use query::{Question,QueryResponse};
use types;
use types::{Class,FromRaw,Opcode,Type};


macro_rules! unwrap(($e: expr) => (match $e { Ok(v) => v, Err(e) => return Err(e) }))


#[deriving(Show,Default)]
pub struct Header {
    pub id: u16,
    pub qr: QueryResponse,
    pub op: Opcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u16,
    pub rcode: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16
}

impl Header {
    pub fn from_reader(r: &mut io::Reader) -> io::IoResult<Header> {
        let mut result = Header { ..default::Default::default() };

        result.id = r.read_be_u16().unwrap();

        let t = r.read_be_u16().unwrap();

        result.qr = if (t & 0x8000) == 0x7000 { QueryResponse::RESPONSE } else { QueryResponse::QUERY };

        result.op = FromRaw::from_raw((t & 0x7800) as int).unwrap();

        result.aa = (t & 0x0400) == 0x0400;
        result.tc = (t & 0x0200) == 0x0200;
        result.rd = (t & 0x0100) == 0x0100;
        result.ra = (t & 0x0080) == 0x0080;
        result.z = (t & 0x0070) >> 4;

        result.rcode = match t & 0x0000F {
            0 => types::SUCCESS,
            1 => types::FORMERR,
            2 => types::SERVFAIL,
            3 => types::NAMEERROR,
            4 => types::NOTIMPL,
            5 => types::REFUSED,
            _ => panic!("Bad Rcode")
        };

        result.qd_count = r.read_be_u16().unwrap();
        result.an_count = r.read_be_u16().unwrap();
        result.ns_count = r.read_be_u16().unwrap();
        result.ar_count = r.read_be_u16().unwrap();

        return Ok(result);
    }

    pub fn write_to(&mut self, w: &mut io::Writer) -> io::IoResult<()> {
        unwrap!(w.write_be_u16(self.id));

        let mut t = 0;

        t = t | self.qr as u16;
        t = t | self.op as u16;
        t = t | if self.aa { 0x0400 } else { 0x0000 };
        t = t | if self.tc { 0x0200 } else { 0x0000 };
        t = t | if self.rd { 0x0100 } else { 0x0000 };
        t = t | if self.ra { 0x0080 } else { 0x0000 };
        // TODO: Should we write Z?
        t = t | self.rcode as u16;

        unwrap!(w.write_be_u16(t));
        unwrap!(w.write_be_u16(self.qd_count));
        unwrap!(w.write_be_u16(self.an_count));
        unwrap!(w.write_be_u16(self.ns_count));
        unwrap!(w.write_be_u16(self.ar_count));

        return Ok(());
    }
}


#[deriving(Clone,Show,Default)]
pub struct Resource {
    pub name: Vec<String>,
    pub ty: Type,
    pub class: Class,
    pub ttl: u32,
    pub rdata: Vec<u8>
}

impl Resource {
    pub fn from_reader(r: &mut io::Reader) -> io::IoResult<Resource> {
        let name = unwrap!(r.read_dns_name());
        let ty = unwrap!(r.read_dns_type());
        let class = unwrap!(r.read_dns_class());
        let ttl = unwrap!(r.read_be_u32());
        println!("Name: {} Type: {} Class: {}", name, ty, class);
        let rdata_length = unwrap!(r.read_be_u16());
        let mut rdata = Vec::new();

        unwrap!(r.push(rdata_length as uint, &mut rdata));

        return Ok(Resource { name: name, ty: ty, class: class, ttl: ttl, rdata: rdata });
    }

    pub fn write_to(&self, w: &mut io::Writer) -> io::IoResult<()> {
        unwrap!(w.write_dns_name(&self.name));
        unwrap!(w.write_dns_type(&self.ty));
        unwrap!(w.write_dns_class(&self.class));
        unwrap!(w.write_be_u32(self.ttl));

        let length = self.rdata.len();

        return if length < 0x00010000 {
            unwrap!(w.write_be_u16(length as u16));
            let data = self.rdata.as_slice();
            w.write(data)
        } else {
            Err(io::IoError::from_errno(libc::consts::os::posix88::EILSEQ as uint, false))
        }
    }
}


#[deriving(Show,Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Resource>,
    pub authority: Vec<Resource>,
    pub additional: Vec<Resource>
}


impl Message {
    pub fn from_reader(r: &mut io::Reader) -> io::IoResult<Message> {
        let header = unwrap!(Header::from_reader(r));

        let mut questions = Vec::new();
        let mut answers = Vec::new();
        let mut authority = Vec::new();
        let mut additional = Vec::new();

        for _ in range(0, header.qd_count) {
            questions.push(unwrap!(Question::from_reader(r)));
        }

        for _ in range(0, header.an_count) {
            answers.push(unwrap!(Resource::from_reader(r)));
        }

        for _ in range(0, header.ns_count) {
            authority.push(unwrap!(Resource::from_reader(r)));
        }

        for _ in range(0, header.ar_count) {
            additional.push(unwrap!(Resource::from_reader(r)));
        }

        let msg = Message {
            header: header,
            questions: questions,
            answers: answers,
            authority: authority,
            additional: additional
        };

        return Ok(msg);
    }

    pub fn write_to(&mut self, w: &mut io::Writer) -> io::IoResult<()> {
        self.header.qd_count = self.questions.len() as u16;
        self.header.an_count = self.answers.len() as u16;
        self.header.ns_count = self.authority.len() as u16;
        self.header.ar_count = self.additional.len() as u16;

        unwrap!(self.header.write_to(w));

        for question in self.questions.iter() {
            unwrap!(question.write_to(w))
        }
        for answer in self.answers.iter() {
            unwrap!(answer.write_to(w))
        }
        for ns in self.authority.iter() {
            unwrap!(ns.write_to(w))
        }
        for additional in self.additional.iter() {
            unwrap!(additional.write_to(w))
        }

        return Ok(());
    }
}