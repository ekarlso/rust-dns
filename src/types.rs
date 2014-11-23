use std::str::FromStr;

pub trait FromRaw {
    fn from_raw (r: int) -> Self;
}

pub enum Cert {
    PKIX = 1,
    SPKI = 2,
    PGP = 3,
    IPKIX = 4,
    ISPKI = 5,
    IPGP = 6,
    ACPKIX = 7,
    IACPKIX = 8,
    URI = 253,
    OID = 254
}

impl FromStr for Cert {
    fn from_str(s: &str) -> Option<Cert> {
        let i = match s {
            "PKIX"         => Cert::PKIX,
            "SPKI"         => Cert::SPKI,
            "PGP"          => Cert::PGP,
            "IPKIX"        => Cert::IPKIX,
            "ISPKI"        => Cert::ISPKI,
            "IPGP"         => Cert::IPGP,
            "ACPKIX"       => Cert::ACPKIX,
            "IACPKIX"      => Cert::IACPKIX,
            "URI"          => Cert::URI,
            "OID"          => Cert::OID,
            _              => panic!("Invalid Type")
        };

        Some(i)
    }
}

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

// Return codes
pub const SUCCESS: u16 = 0;
pub const FORMERR: u16 = 1;
pub const SERVFAIL: u16 = 2;
pub const NAMEERROR: u16 = 3;
pub const NOTIMPL: u16 = 4;
pub const REFUSED: u16 = 5;
pub const YXDOMAIN: u16 = 6;
pub const YXRRSET: u16 = 7;
pub const NXRRSET: u16 = 8;
pub const NOTAUTH: u16 = 9;
pub const NOTZONE: u16 = 10;
pub const BADSIG: u16 = 16;  // this
pub const BADVERS: u16 = 16; // ... and this  have the same discriminant
pub const BADKEY: u16 = 17;
pub const BADTIME: u16 = 18;
pub const BADMODE: u16 = 19;
pub const BADNAME: u16 = 20;
pub const BADALG: u16 = 21;
pub const BADTRUNC: u16 = 22;


pub fn rcode_from_str(s: &str) -> u16 {
    match s {
        "SUCCESS"   => SUCCESS,
        "FORMERR"   => FORMERR,
        "SERVFAIL"  => SERVFAIL,
        "NAMEERROR" => NAMEERROR,
        "NOTIMPL"   => NOTIMPL,
        "REFUSED"   => REFUSED,
        "YXDOMAIN"  => YXDOMAIN,
        "YXRRSET"   => YXRRSET,
        "NXRRSET"   => NXRRSET,
        "NOTAUTH"   => NOTAUTH,
        "NOTZONE"   => NOTZONE,
        "BADSIG"    => BADSIG,
        "BADVERS"   => BADVERS,
        "BADKEY"    => BADKEY,
        "BADTIME"   => BADTIME,
        "BADMODE"   => BADMODE,
        "BADNAME"   => BADNAME,
        "BADALG"    => BADALG,
        "BADTRUNC"  => BADTRUNC,
        x           => panic!("invalid rcode {}", s)
    }
}

pub enum Type {
    NONE = 0,
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAP = 22,
    NSAPPTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30,
    EID = 31,
    NIMLOC = 32,
    SRV = 33,
    ATMA = 34,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    DNAME = 39,
    OPT = 41,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    HIP = 55,
    NINFO = 56,
    RKEY = 57,
    TALINK = 58,
    CDS = 59,
    OPENPGPKEY = 61,
    SPF = 99,
    UINFO = 100,
    UID = 101,
    GID = 102,
    UNSPEC = 103,
    NID = 104,
    L32 = 105,
    L64 = 106,
    LP = 107,
    EUI48 = 108,
    EUI64 = 109,
    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ANY = 255,
    URI = 256,
    CAA = 257,
    TA = 32768,
    DLV = 32769,
    Reserved = 65535,
}

impl FromStr for Type {
   fn from_str(s: &str) -> Option<Type> {
        let i = match s {
            "NONE"         => Type::NONE,
            "A"            => Type::A,
            "NS"           => Type::NS,
            "MD"           => Type::MD,
            "MF"           => Type::MF,
            "CNAME"        => Type::CNAME,
            "SOA"          => Type::SOA,
            "MB"           => Type::MB,
            "MG"           => Type::MG,
            "MR"           => Type::MR,
            "NULL"         => Type::NULL,
            "WKS"          => Type::WKS,
            "PTR"          => Type::PTR,
            "HINFO"        => Type::HINFO,
            "MINFO"        => Type::MINFO,
            "MX"           => Type::MX,
            "TXT"          => Type::TXT,
            "RP"           => Type::RP,
            "AFSDB"        => Type::AFSDB,
            "X25"          => Type::X25,
            "ISDN"         => Type::ISDN,
            "RT"           => Type::RT,
            "NSAP"         => Type::NSAP,
            "NSAPPTR"      => Type::NSAPPTR,
            "SIG"          => Type::SIG,
            "KEY"          => Type::KEY,
            "PX"           => Type::PX,
            "GPOS"         => Type::GPOS,
            "AAAA"         => Type::AAAA,
            "LOC"          => Type::LOC,
            "NXT"          => Type::NXT,
            "EID"          => Type::EID,
            "NIMLOC"       => Type::NIMLOC,
            "SRV"          => Type::SRV,
            "ATMA"         => Type::ATMA,
            "NAPTR"        => Type::NAPTR,
            "KX"           => Type::KX,
            "CERT"         => Type::CERT,
            "DNAME"        => Type::DNAME,
            "OPT"          => Type::OPT,
            "DS"           => Type::DS,
            "SSHFP"        => Type::SSHFP,
            "IPSECKEY"     => Type::IPSECKEY,
            "RRSIG"        => Type::RRSIG,
            "NSEC"         => Type::NSEC,
            "DNSKEY"       => Type::DNSKEY,
            "DHCID"        => Type::DHCID,
            "NSEC3"        => Type::NSEC3,
            "NSEC3PARAM"   => Type::NSEC3PARAM,
            "TLSA"         => Type::TLSA,
            "HIP"          => Type::HIP,
            "NINFO"        => Type::NINFO,
            "RKEY"         => Type::RKEY,
            "TALINK"       => Type::TALINK,
            "CDS"          => Type::CDS,
            "OPENPGPKEY"   => Type::OPENPGPKEY,
            "SPF"          => Type::SPF,
            "UINFO"        => Type::UINFO,
            "UID"          => Type::UID,
            "GID"          => Type::GID,
            "UNSPEC"       => Type::UNSPEC,
            "NID"          => Type::NID,
            "L32"          => Type::L32,
            "L64"          => Type::L64,
            "LP"           => Type::LP,
            "EUI48"        => Type::EUI48,
            "EUI64"        => Type::EUI64,
            "TKEY"         => Type::TKEY,
            "TSIG"         => Type::TSIG,
            "IXFR"         => Type::IXFR,
            "AXFR"         => Type::AXFR,
            "MAILB"        => Type::MAILB,
            "MAILA"        => Type::MAILA,
            "ANY"          => Type::ANY,
            "URI"          => Type::URI,
            "CAA"          => Type::CAA,
            "TA"           => Type::TA,
            "DLV"          => Type::DLV,
            "Reserved"     => Type::Reserved,
            _              => panic!("Invalid Type")
        };

        Some(i)
    }

}

impl FromRaw for Type {
    fn from_raw(r: int) -> Type {
        match r {
            0       => Type::NONE,
            1       => Type::A,
            2       => Type::NS,
            3       => Type::MD,
            4       => Type::MF,
            5       => Type::CNAME,
            6       => Type::SOA,
            7       => Type::MB,
            8       => Type::MG,
            9       => Type::MR,
            10      => Type::NULL,
            11      => Type::WKS,
            12      => Type::PTR,
            13      => Type::HINFO,
            14      => Type::MINFO,
            15      => Type::MX,
            16      => Type::TXT,
            17      => Type::RP,
            18      => Type::AFSDB,
            19      => Type::X25,
            20      => Type::ISDN,
            21      => Type::RT,
            22      => Type::NSAP,
            23      => Type::NSAPPTR,
            24      => Type::SIG,
            25      => Type::KEY,
            26      => Type::PX,
            27      => Type::GPOS,
            28      => Type::AAAA,
            29      => Type::LOC,
            30      => Type::NXT,
            31      => Type::EID,
            32      => Type::NIMLOC,
            33      => Type::SRV,
            34      => Type::ATMA,
            35      => Type::NAPTR,
            36      => Type::KX,
            37      => Type::CERT,
            39      => Type::DNAME,
            41      => Type::OPT,
            43      => Type::DS,
            44      => Type::SSHFP,
            45      => Type::IPSECKEY,
            46      => Type::RRSIG,
            47      => Type::NSEC,
            48      => Type::DNSKEY,
            49      => Type::DHCID,
            50      => Type::NSEC3,
            51      => Type::NSEC3PARAM,
            52      => Type::TLSA,
            55      => Type::HIP,
            56      => Type::NINFO,
            57      => Type::RKEY,
            58      => Type::TALINK,
            59      => Type::CDS,
            61      => Type::OPENPGPKEY,
            99      => Type::SPF,
            100     => Type::UINFO,
            101     => Type::UID,
            102     => Type::GID,
            103     => Type::UNSPEC,
            104     => Type::NID,
            105     => Type::L32,
            106     => Type::L64,
            107     => Type::LP,
            108     => Type::EUI48,
            109     => Type::EUI64,
            249     => Type::TKEY,
            250     => Type::TSIG,
            251     => Type::IXFR,
            252     => Type::AXFR,
            253     => Type::MAILB,
            254     => Type::MAILA,
            255     => Type::ANY,
            256     => Type::URI,
            257     => Type::CAA,
            32768   => Type::TA,
            32769   => Type::DLV,
            65535   => Type::Reserved,
            _       => panic!("Invalid Type")
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::from_str;
    use types;

    #[test]
    fn test_a_from_raw() {
        assert_eq!(types::Type::A, types::Type.from_raw(1));
    }

    #[test]
    fn test_success() {
        assert_eq!(types::SUCCESS, types::rcode_from_str("SUCCESS"));
    }

    #[test]
    fn test_formerr() {
        assert_eq!(types::FORMERR, types::rcode_from_str("FORMERR"));
    }

    #[test]
    fn test_servfail() {
        assert_eq!(types::SERVFAIL, types::rcode_from_str("SERVFAIL"));
    }

    #[test]
    fn test_nameerror() {
        assert_eq!(types::NAMEERROR, types::rcode_from_str("NAMEERROR"));
    }

    #[test]
    fn test_notimpl() {
        assert_eq!(types::NOTIMPL, types::rcode_from_str("NOTIMPL"));
    }

    #[test]
    fn test_refused() {
        assert_eq!(types::REFUSED, types::rcode_from_str("REFUSED"));
    }


    #[test]
    fn test_yxdomain() {
        assert_eq!(types::YXDOMAIN, types::rcode_from_str("YXDOMAIN"));
    }

    #[test]
    fn test_yxrrset() {
        assert_eq!(types::YXRRSET, types::rcode_from_str("YXRRSET"));
    }

    #[test]
    fn test_nxrrset() {
        assert_eq!(types::NXRRSET, types::rcode_from_str("NXRRSET"));
    }

    #[test]
    fn test_notauth() {
        assert_eq!(types::NOTAUTH, types::rcode_from_str("NOTAUTH"));
    }

    #[test]
    fn test_notzone() {
        assert_eq!(types::NOTZONE, types::rcode_from_str("NOTZONE"));
    }

    #[test]
    fn test_badsig() {
        assert_eq!(types::BADSIG, types::rcode_from_str("BADSIG"));
    }

    #[test]
    fn test_badvers() {
        assert_eq!(types::BADVERS, types::rcode_from_str("BADVERS"));
    }

    #[test]
    fn test_badkey() {
        assert_eq!(types::BADKEY, types::rcode_from_str("BADKEY"));
    }

    #[test]
    fn test_badtime() {
        assert_eq!(types::BADTIME, types::rcode_from_str("BADTIME"));
    }

    #[test]
    fn test_badmode() {
        assert_eq!(types::BADMODE, types::rcode_from_str("BADMODE"));
    }

    #[test]
    fn test_badname() {
        assert_eq!(types::BADNAME, types::rcode_from_str("BADNAME"));
    }

    #[test]
    fn test_badalg() {
        assert_eq!(types::BADALG, types::rcode_from_str("BADALG"));
    }

    #[test]
    fn test_badtrunc() {
        assert_eq!(types::BADTRUNC, types::rcode_from_str("BADTRUNC"));
    }
}