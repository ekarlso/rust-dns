use std::default;
use std::str::FromStr;

pub trait FromRaw {
    fn from_raw (r: int) -> Option<Self>;
}

#[deriving(Clone,Show,PartialEq)]
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

impl FromRaw for Cert {
    fn from_raw (r: int) -> Option<Cert> {
        match r {
            1   => Some(Cert::PKIX),
            2   => Some(Cert::SPKI),
            3   => Some(Cert::PGP),
            4   => Some(Cert::IPKIX),
            5   => Some(Cert::ISPKI),
            6   => Some(Cert::IPGP),
            7   => Some(Cert::ACPKIX),
            8   => Some(Cert::IACPKIX),
            253 => Some(Cert::URI),
            254 => Some(Cert::OID),
            _   => None
        }
    }
}

impl FromStr for Cert {
    fn from_str(s: &str) -> Option<Cert> {
        match s {
            "PKIX"         => Some(Cert::PKIX),
            "SPKI"         => Some(Cert::SPKI),
            "PGP"          => Some(Cert::PGP),
            "IPKIX"        => Some(Cert::IPKIX),
            "ISPKI"        => Some(Cert::ISPKI),
            "IPGP"         => Some(Cert::IPGP),
            "ACPKIX"       => Some(Cert::ACPKIX),
            "IACPKIX"      => Some(Cert::IACPKIX),
            "URI"          => Some(Cert::URI),
            "OID"          => Some(Cert::OID),
            _              => None
        }
    }
}

#[deriving(Clone,Show,PartialEq)]
pub enum Class {
    INET = 1,
    CSNET = 2,
    CHAOS = 3,
    HESIOD = 4,
    NONE = 254,
    ANY = 255
}

impl FromRaw for Class {
    fn from_raw (r: int) -> Option<Class> {
        match r {
            1       => Some(Class::INET),
            2       => Some(Class::CSNET),
            3       => Some(Class::CHAOS),
            4       => Some(Class::HESIOD),
            254     => Some(Class::NONE),
            255     => Some(Class::ANY),
            _       => None
        }
    }
}

impl FromStr for Class {
    fn from_str(s: &str) -> Option<Class> {
        match s {
            "INET"         => Some(Class::INET),
            "CSNET"        => Some(Class::CSNET),
            "CHAOS"        => Some(Class::CHAOS),
            "HESIOD"       => Some(Class::HESIOD),
            "NONE"         => Some(Class::NONE),
            "ANY"          => Some(Class::ANY),
            _              => None
        }
    }
}

impl default::Default for Class {
  fn default() -> Class { Class::INET }
}

#[repr(u16)]
#[deriving(Clone,Show,PartialEq)]
pub enum Opcode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5,
}

impl FromRaw for Opcode {
    fn from_raw(r: int) -> Option<Opcode> {
        match r {
            0   => Some(Opcode::QUERY),
            1   => Some(Opcode::IQUERY),
            2   => Some(Opcode::STATUS),
            4   => Some(Opcode::NOTIFY),
            5   => Some(Opcode::UPDATE),
            _   => None
        }
    }
}

impl FromStr for Opcode {
    fn from_str(s: &str) -> Option<Opcode> {
        match s {
            "QUERY"        => Some(Opcode::QUERY),
            "IQUERY"       => Some(Opcode::IQUERY),
            "STATUS"       => Some(Opcode::STATUS),
            "NOTIFY"       => Some(Opcode::NOTIFY),
            "UPDATE"       => Some(Opcode::UPDATE),
            _              => None
        }
    }
}

impl default::Default for Opcode {
  fn default() -> Opcode { Opcode::QUERY }
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


pub fn rcode_from_str(s: &str) -> Option<u16> {
    match s {
        "SUCCESS"   => Some(SUCCESS),
        "FORMERR"   => Some(FORMERR),
        "SERVFAIL"  => Some(SERVFAIL),
        "NAMEERROR" => Some(NAMEERROR),
        "NOTIMPL"   => Some(NOTIMPL),
        "REFUSED"   => Some(REFUSED),
        "YXDOMAIN"  => Some(YXDOMAIN),
        "YXRRSET"   => Some(YXRRSET),
        "NXRRSET"   => Some(NXRRSET),
        "NOTAUTH"   => Some(NOTAUTH),
        "NOTZONE"   => Some(NOTZONE),
        "BADSIG"    => Some(BADSIG),
        "BADVERS"   => Some(BADVERS),
        "BADKEY"    => Some(BADKEY),
        "BADTIME"   => Some(BADTIME),
        "BADMODE"   => Some(BADMODE),
        "BADNAME"   => Some(BADNAME),
        "BADALG"    => Some(BADALG),
        "BADTRUNC"  => Some(BADTRUNC),
        x           => panic!("invalid rcode {}", s)
    }
}

#[repr(u16)]
#[deriving(Clone,Show,PartialEq)]
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

impl FromRaw for Type {
    fn from_raw(r: int) -> Option<Type> {
        match r {
            0       => Some(Type::NONE),
            1       => Some(Type::A),
            2       => Some(Type::NS),
            3       => Some(Type::MD),
            4       => Some(Type::MF),
            5       => Some(Type::CNAME),
            6       => Some(Type::SOA),
            7       => Some(Type::MB),
            8       => Some(Type::MG),
            9       => Some(Type::MR),
            10      => Some(Type::NULL),
            11      => Some(Type::WKS),
            12      => Some(Type::PTR),
            13      => Some(Type::HINFO),
            14      => Some(Type::MINFO),
            15      => Some(Type::MX),
            16      => Some(Type::TXT),
            17      => Some(Type::RP),
            18      => Some(Type::AFSDB),
            19      => Some(Type::X25),
            20      => Some(Type::ISDN),
            21      => Some(Type::RT),
            22      => Some(Type::NSAP),
            23      => Some(Type::NSAPPTR),
            24      => Some(Type::SIG),
            25      => Some(Type::KEY),
            26      => Some(Type::PX),
            27      => Some(Type::GPOS),
            28      => Some(Type::AAAA),
            29      => Some(Type::LOC),
            30      => Some(Type::NXT),
            31      => Some(Type::EID),
            32      => Some(Type::NIMLOC),
            33      => Some(Type::SRV),
            34      => Some(Type::ATMA),
            35      => Some(Type::NAPTR),
            36      => Some(Type::KX),
            37      => Some(Type::CERT),
            39      => Some(Type::DNAME),
            41      => Some(Type::OPT),
            43      => Some(Type::DS),
            44      => Some(Type::SSHFP),
            45      => Some(Type::IPSECKEY),
            46      => Some(Type::RRSIG),
            47      => Some(Type::NSEC),
            48      => Some(Type::DNSKEY),
            49      => Some(Type::DHCID),
            50      => Some(Type::NSEC3),
            51      => Some(Type::NSEC3PARAM),
            52      => Some(Type::TLSA),
            55      => Some(Type::HIP),
            56      => Some(Type::NINFO),
            57      => Some(Type::RKEY),
            58      => Some(Type::TALINK),
            59      => Some(Type::CDS),
            61      => Some(Type::OPENPGPKEY),
            99      => Some(Type::SPF),
            100     => Some(Type::UINFO),
            101     => Some(Type::UID),
            102     => Some(Type::GID),
            103     => Some(Type::UNSPEC),
            104     => Some(Type::NID),
            105     => Some(Type::L32),
            106     => Some(Type::L64),
            107     => Some(Type::LP),
            108     => Some(Type::EUI48),
            109     => Some(Type::EUI64),
            249     => Some(Type::TKEY),
            250     => Some(Type::TSIG),
            251     => Some(Type::IXFR),
            252     => Some(Type::AXFR),
            253     => Some(Type::MAILB),
            254     => Some(Type::MAILA),
            255     => Some(Type::ANY),
            256     => Some(Type::URI),
            257     => Some(Type::CAA),
            32768   => Some(Type::TA),
            32769   => Some(Type::DLV),
            65535   => Some(Type::Reserved),
            _       => None
        }
    }
}

impl FromStr for Type {
   fn from_str(s: &str) -> Option<Type> {
        match s {
            "NONE"         => Some(Type::NONE),
            "A"            => Some(Type::A),
            "NS"           => Some(Type::NS),
            "MD"           => Some(Type::MD),
            "MF"           => Some(Type::MF),
            "CNAME"        => Some(Type::CNAME),
            "SOA"          => Some(Type::SOA),
            "MB"           => Some(Type::MB),
            "MG"           => Some(Type::MG),
            "MR"           => Some(Type::MR),
            "NULL"         => Some(Type::NULL),
            "WKS"          => Some(Type::WKS),
            "PTR"          => Some(Type::PTR),
            "HINFO"        => Some(Type::HINFO),
            "MINFO"        => Some(Type::MINFO),
            "MX"           => Some(Type::MX),
            "TXT"          => Some(Type::TXT),
            "RP"           => Some(Type::RP),
            "AFSDB"        => Some(Type::AFSDB),
            "X25"          => Some(Type::X25),
            "ISDN"         => Some(Type::ISDN),
            "RT"           => Some(Type::RT),
            "NSAP"         => Some(Type::NSAP),
            "NSAPPTR"      => Some(Type::NSAPPTR),
            "SIG"          => Some(Type::SIG),
            "KEY"          => Some(Type::KEY),
            "PX"           => Some(Type::PX),
            "GPOS"         => Some(Type::GPOS),
            "AAAA"         => Some(Type::AAAA),
            "LOC"          => Some(Type::LOC),
            "NXT"          => Some(Type::NXT),
            "EID"          => Some(Type::EID),
            "NIMLOC"       => Some(Type::NIMLOC),
            "SRV"          => Some(Type::SRV),
            "ATMA"         => Some(Type::ATMA),
            "NAPTR"        => Some(Type::NAPTR),
            "KX"           => Some(Type::KX),
            "CERT"         => Some(Type::CERT),
            "DNAME"        => Some(Type::DNAME),
            "OPT"          => Some(Type::OPT),
            "DS"           => Some(Type::DS),
            "SSHFP"        => Some(Type::SSHFP),
            "IPSECKEY"     => Some(Type::IPSECKEY),
            "RRSIG"        => Some(Type::RRSIG),
            "NSEC"         => Some(Type::NSEC),
            "DNSKEY"       => Some(Type::DNSKEY),
            "DHCID"        => Some(Type::DHCID),
            "NSEC3"        => Some(Type::NSEC3),
            "NSEC3PARAM"   => Some(Type::NSEC3PARAM),
            "TLSA"         => Some(Type::TLSA),
            "HIP"          => Some(Type::HIP),
            "NINFO"        => Some(Type::NINFO),
            "RKEY"         => Some(Type::RKEY),
            "TALINK"       => Some(Type::TALINK),
            "CDS"          => Some(Type::CDS),
            "OPENPGPKEY"   => Some(Type::OPENPGPKEY),
            "SPF"          => Some(Type::SPF),
            "UINFO"        => Some(Type::UINFO),
            "UID"          => Some(Type::UID),
            "GID"          => Some(Type::GID),
            "UNSPEC"       => Some(Type::UNSPEC),
            "NID"          => Some(Type::NID),
            "L32"          => Some(Type::L32),
            "L64"          => Some(Type::L64),
            "LP"           => Some(Type::LP),
            "EUI48"        => Some(Type::EUI48),
            "EUI64"        => Some(Type::EUI64),
            "TKEY"         => Some(Type::TKEY),
            "TSIG"         => Some(Type::TSIG),
            "IXFR"         => Some(Type::IXFR),
            "AXFR"         => Some(Type::AXFR),
            "MAILB"        => Some(Type::MAILB),
            "MAILA"        => Some(Type::MAILA),
            "ANY"          => Some(Type::ANY),
            "URI"          => Some(Type::URI),
            "CAA"          => Some(Type::CAA),
            "TA"           => Some(Type::TA),
            "DLV"          => Some(Type::DLV),
            "Reserved"     => Some(Type::Reserved),
            _              => None
        }
    }
}

impl default::Default for Type {
  fn default() -> Type { Type::A }
}

#[cfg(test)]
mod test {
    use std::str::from_str;
    use types;

    use types::FromRaw;
    use types::Cert;
    use types::Class;
    use types::Opcode;
    use types::Type;

    // Tests for Certs
    #[test]
    fn test_cert_pkix_from_raw() {
        let t: Cert = FromRaw::from_raw(1).unwrap();
        assert_eq!(Cert::PKIX, t);
    }

    #[test]
    fn test_cert_spki_from_raw() {
        let t: Cert = FromRaw::from_raw(2).unwrap();
        assert_eq!(Cert::SPKI, t);
    }

    #[test]
    fn test_cert_pgp_from_raw() {
        let t: Cert = FromRaw::from_raw(3).unwrap();
        assert_eq!(Cert::PGP, t);
    }

    #[test]
    fn test_cert_ipkix_from_raw() {
        let t: Cert = FromRaw::from_raw(4).unwrap();
        assert_eq!(Cert::IPKIX, t);
    }

    #[test]
    fn test_cert_ispki_from_raw() {
        let t: Cert = FromRaw::from_raw(5).unwrap();
        assert_eq!(Cert::ISPKI, t);
    }

    #[test]
    fn test_cert_ipgp_from_raw() {
        let t: Cert = FromRaw::from_raw(6).unwrap();
        assert_eq!(Cert::IPGP, t);
    }

    #[test]
    fn test_cert_acpkix_from_raw() {
        let t: Cert = FromRaw::from_raw(7).unwrap();
        assert_eq!(Cert::ACPKIX, t);
    }

    #[test]
    fn test_cert_iacpkix_from_raw() {
        let t: Cert = FromRaw::from_raw(8).unwrap();
        assert_eq!(Cert::IACPKIX, t);
    }

    #[test]
    fn test_cert_uri_from_raw() {
        let t: Cert = FromRaw::from_raw(253).unwrap();
        assert_eq!(Cert::URI, t);
    }

    #[test]
    fn test_cert_oid_from_raw() {
        let t: Cert = FromRaw::from_raw(254).unwrap();
        assert_eq!(Cert::OID, t);
    }

    #[test]
    fn test_cert_pkix_from_str() { assert_eq!(Cert::PKIX, from_str::<Cert>("PKIX").unwrap()); }

    #[test]
    fn test_cert_spki_from_str() { assert_eq!(Cert::SPKI, from_str::<Cert>("SPKI").unwrap()); }

    #[test]
    fn test_cert_pgp_from_str() { assert_eq!(Cert::PGP, from_str::<Cert>("PGP").unwrap()); }

    #[test]
    fn test_cert_ipkix_from_str() { assert_eq!(Cert::IPKIX, from_str::<Cert>("IPKIX").unwrap()); }

    #[test]
    fn test_cert_ispki_from_str() { assert_eq!(Cert::ISPKI, from_str::<Cert>("ISPKI").unwrap()); }

    #[test]
    fn test_cert_ipgp_from_str() { assert_eq!(Cert::IPGP, from_str::<Cert>("IPGP").unwrap()); }

    #[test]
    fn test_cert_acpkix_from_str() { assert_eq!(Cert::ACPKIX, from_str::<Cert>("ACPKIX").unwrap()); }

    #[test]
    fn test_cert_iacpkix_from_str() { assert_eq!(Cert::IACPKIX, from_str::<Cert>("IACPKIX").unwrap()); }

    #[test]
    fn test_cert_uri_from_str() { assert_eq!(Cert::URI, from_str::<Cert>("URI").unwrap()); }

    #[test]
    fn test_cert_oid_from_str() { assert_eq!(Cert::OID, from_str::<Cert>("OID").unwrap()); }

    // Tests for Classes
    #[test]
    fn test_class_inet_from_raw() {
        let t: Class = FromRaw::from_raw(1).unwrap();
        assert_eq!(Class::INET, t);
    }

    #[test]
    fn test_class_csnet_from_raw() {
        let t: Class = FromRaw::from_raw(2).unwrap();
        assert_eq!(Class::CSNET, t);
    }

    #[test]
    fn test_class_chaos_from_raw() {
        let t: Class = FromRaw::from_raw(3).unwrap();
        assert_eq!(Class::CHAOS, t);
    }

    #[test]
    fn test_class_hesiod_from_raw() {
        let t: Class = FromRaw::from_raw(4).unwrap();
        assert_eq!(Class::HESIOD, t);
    }

    #[test]
    fn test_class_none_from_raw() {
        let t: Class = FromRaw::from_raw(254).unwrap();
        assert_eq!(Class::NONE, t);
    }

    #[test]
    fn test_class_any_from_raw() {
        let t: Class = FromRaw::from_raw(255).unwrap();
        assert_eq!(Class::ANY, t);
    }

    #[test]
    fn test_class_inet_from_str() { assert_eq!(Class::INET, from_str::<Class>("INET").unwrap()); }

    #[test]
    fn test_class_csnet_from_str() { assert_eq!(Class::CSNET, from_str::<Class>("CSNET").unwrap()); }

    #[test]
    fn test_class_chaos_from_str() { assert_eq!(Class::CHAOS, from_str::<Class>("CHAOS").unwrap()); }

    #[test]
    fn test_class_hesiod_from_str() { assert_eq!(Class::HESIOD, from_str::<Class>("HESIOD").unwrap()); }

    #[test]
    fn test_class_none_from_str() { assert_eq!(Class::NONE, from_str::<Class>("NONE").unwrap()); }

    #[test]
    fn test_class_any_from_str() { assert_eq!(Class::ANY, from_str::<Class>("ANY").unwrap()); }

    // Tests for Opcodes
    #[test]
    fn test_opcode_query_from_raw() {
        let t: Opcode = FromRaw::from_raw(0).unwrap();
        assert_eq!(Opcode::QUERY, t);
    }
    #[test]
    fn test_opcode_iquery_from_raw() {
        let t: Opcode = FromRaw::from_raw(1).unwrap();
        assert_eq!(Opcode::IQUERY, t);
    }
    #[test]
    fn test_opcode_status_from_raw() {
        let t: Opcode = FromRaw::from_raw(2).unwrap();
        assert_eq!(Opcode::STATUS, t);
    }
    #[test]
    fn test_opcode_notify_from_raw() {
        let t: Opcode = FromRaw::from_raw(4).unwrap();
        assert_eq!(Opcode::NOTIFY, t);
    }
    #[test]
    fn test_opcode_update_from_raw() {
        let t: Opcode = FromRaw::from_raw(5).unwrap();
        assert_eq!(Opcode::UPDATE, t);
    }
    #[test]
    fn test_opcode_query_from_str() { assert_eq!(Opcode::QUERY, from_str::<Opcode>("QUERY").unwrap()); }

    #[test]
    fn test_opcode_iquery_from_str() { assert_eq!(Opcode::IQUERY, from_str::<Opcode>("IQUERY").unwrap()); }

    #[test]
    fn test_opcode_status_from_str() { assert_eq!(Opcode::STATUS, from_str::<Opcode>("STATUS").unwrap()); }

    #[test]
    fn test_opcode_notify_from_str() { assert_eq!(Opcode::NOTIFY, from_str::<Opcode>("NOTIFY").unwrap()); }

    #[test]
    fn test_opcode_update_from_str() { assert_eq!(Opcode::UPDATE, from_str::<Opcode>("UPDATE").unwrap()); }

    // Tests for RRTypes
    #[test]
    fn test_rtype_none_from_str() {
        assert_eq!(Type::NONE, from_str::<Type>("NONE").unwrap());
    }

    #[test]
    fn test_rtype_a_from_str() {
        assert_eq!(Type::A, from_str::<Type>("A").unwrap());
    }

    #[test]
    fn test_rtype_ns_from_str() {
        assert_eq!(Type::NS, from_str::<Type>("NS").unwrap());
    }

    #[test]
    fn test_rtype_md_from_str() {
        assert_eq!(Type::MD, from_str::<Type>("MD").unwrap());
    }

    #[test]
    fn test_rtype_mf_from_str() {
        assert_eq!(Type::MF, from_str::<Type>("MF").unwrap());
    }

    #[test]
    fn test_rtype_cname_from_str() {
        assert_eq!(Type::CNAME, from_str::<Type>("CNAME").unwrap());
    }

    #[test]
    fn test_rtype_soa_from_str() {
        assert_eq!(Type::SOA, from_str::<Type>("SOA").unwrap());
    }

    #[test]
    fn test_rtype_mb_from_str() {
        assert_eq!(Type::MB, from_str::<Type>("MB").unwrap());
    }

    #[test]
    fn test_rtype_mg_from_str() {
        assert_eq!(Type::MG, from_str::<Type>("MG").unwrap());
    }

    #[test]
    fn test_rtype_mr_from_str() {
        assert_eq!(Type::MR, from_str::<Type>("MR").unwrap());
    }

    #[test]
    fn test_rtype_null_from_str() {
        assert_eq!(Type::NULL, from_str::<Type>("NULL").unwrap());
    }

    #[test]
    fn test_rtype_wks_from_str() {
        assert_eq!(Type::WKS, from_str::<Type>("WKS").unwrap());
    }

    #[test]
    fn test_rtype_ptr_from_str() {
        assert_eq!(Type::PTR, from_str::<Type>("PTR").unwrap());
    }

    #[test]
    fn test_rtype_hinfo_from_str() {
        assert_eq!(Type::HINFO, from_str::<Type>("HINFO").unwrap());
    }

    #[test]
    fn test_rtype_minfo_from_str() {
        assert_eq!(Type::MINFO, from_str::<Type>("MINFO").unwrap());
    }

    #[test]
    fn test_rtype_mx_from_str() {
        assert_eq!(Type::MX, from_str::<Type>("MX").unwrap());
    }

    #[test]
    fn test_rtype_txt_from_str() {
        assert_eq!(Type::TXT, from_str::<Type>("TXT").unwrap());
    }

    #[test]
    fn test_rtype_rp_from_str() {
        assert_eq!(Type::RP, from_str::<Type>("RP").unwrap());
    }

    #[test]
    fn test_rtype_afsdb_from_str() {
        assert_eq!(Type::AFSDB, from_str::<Type>("AFSDB").unwrap());
    }

    #[test]
    fn test_rtype_x25_from_str() {
        assert_eq!(Type::X25, from_str::<Type>("X25").unwrap());
    }

    #[test]
    fn test_rtype_isdn_from_str() {
        assert_eq!(Type::ISDN, from_str::<Type>("ISDN").unwrap());
    }

    #[test]
    fn test_rtype_rt_from_str() {
        assert_eq!(Type::RT, from_str::<Type>("RT").unwrap());
    }

    #[test]
    fn test_rtype_nsap_from_str() {
        assert_eq!(Type::NSAP, from_str::<Type>("NSAP").unwrap());
    }

    #[test]
    fn test_rtype_nsapptr_from_str() {
        assert_eq!(Type::NSAPPTR, from_str::<Type>("NSAPPTR").unwrap());
    }

    #[test]
    fn test_rtype_sig_from_str() {
        assert_eq!(Type::SIG, from_str::<Type>("SIG").unwrap());
    }

    #[test]
    fn test_rtype_key_from_str() {
        assert_eq!(Type::KEY, from_str::<Type>("KEY").unwrap());
    }

    #[test]
    fn test_rtype_px_from_str() {
        assert_eq!(Type::PX, from_str::<Type>("PX").unwrap());
    }

    #[test]
    fn test_rtype_gpos_from_str() {
        assert_eq!(Type::GPOS, from_str::<Type>("GPOS").unwrap());
    }

    #[test]
    fn test_rtype_aaaa_from_str() {
        assert_eq!(Type::AAAA, from_str::<Type>("AAAA").unwrap());
    }

    #[test]
    fn test_rtype_loc_from_str() {
        assert_eq!(Type::LOC, from_str::<Type>("LOC").unwrap());
    }

    #[test]
    fn test_rtype_nxt_from_str() {
        assert_eq!(Type::NXT, from_str::<Type>("NXT").unwrap());
    }

    #[test]
    fn test_rtype_eid_from_str() {
        assert_eq!(Type::EID, from_str::<Type>("EID").unwrap());
    }

    #[test]
    fn test_rtype_nimloc_from_str() {
        assert_eq!(Type::NIMLOC, from_str::<Type>("NIMLOC").unwrap());
    }

    #[test]
    fn test_rtype_srv_from_str() {
        assert_eq!(Type::SRV, from_str::<Type>("SRV").unwrap());
    }

    #[test]
    fn test_rtype_atma_from_str() {
        assert_eq!(Type::ATMA, from_str::<Type>("ATMA").unwrap());
    }

    #[test]
    fn test_rtype_naptr_from_str() {
        assert_eq!(Type::NAPTR, from_str::<Type>("NAPTR").unwrap());
    }

    #[test]
    fn test_rtype_kx_from_str() {
        assert_eq!(Type::KX, from_str::<Type>("KX").unwrap());
    }

    #[test]
    fn test_rtype_cert_from_str() {
        assert_eq!(Type::CERT, from_str::<Type>("CERT").unwrap());
    }

    #[test]
    fn test_rtype_dname_from_str() {
        assert_eq!(Type::DNAME, from_str::<Type>("DNAME").unwrap());
    }

    #[test]
    fn test_rtype_opt_from_str() {
        assert_eq!(Type::OPT, from_str::<Type>("OPT").unwrap());
    }

    #[test]
    fn test_rtype_ds_from_str() {
        assert_eq!(Type::DS, from_str::<Type>("DS").unwrap());
    }

    #[test]
    fn test_rtype_sshfp_from_str() {
        assert_eq!(Type::SSHFP, from_str::<Type>("SSHFP").unwrap());
    }

    #[test]
    fn test_rtype_ipseckey_from_str() {
        assert_eq!(Type::IPSECKEY, from_str::<Type>("IPSECKEY").unwrap());
    }

    #[test]
    fn test_rtype_rrsig_from_str() {
        assert_eq!(Type::RRSIG, from_str::<Type>("RRSIG").unwrap());
    }

    #[test]
    fn test_rtype_nsec_from_str() {
        assert_eq!(Type::NSEC, from_str::<Type>("NSEC").unwrap());
    }

    #[test]
    fn test_rtype_dnskey_from_str() {
        assert_eq!(Type::DNSKEY, from_str::<Type>("DNSKEY").unwrap());
    }

    #[test]
    fn test_rtype_dhcid_from_str() {
        assert_eq!(Type::DHCID, from_str::<Type>("DHCID").unwrap());
    }

    #[test]
    fn test_rtype_nsec3_from_str() {
        assert_eq!(Type::NSEC3, from_str::<Type>("NSEC3").unwrap());
    }

    #[test]
    fn test_rtype_nsec3param_from_str() {
        assert_eq!(Type::NSEC3PARAM, from_str::<Type>("NSEC3PARAM").unwrap());
    }

    #[test]
    fn test_rtype_tlsa_from_str() {
        assert_eq!(Type::TLSA, from_str::<Type>("TLSA").unwrap());
    }

    #[test]
    fn test_rtype_hip_from_str() {
        assert_eq!(Type::HIP, from_str::<Type>("HIP").unwrap());
    }

    #[test]
    fn test_rtype_ninfo_from_str() {
        assert_eq!(Type::NINFO, from_str::<Type>("NINFO").unwrap());
    }

    #[test]
    fn test_rtype_rkey_from_str() {
        assert_eq!(Type::RKEY, from_str::<Type>("RKEY").unwrap());
    }

    #[test]
    fn test_rtype_talink_from_str() {
        assert_eq!(Type::TALINK, from_str::<Type>("TALINK").unwrap());
    }

    #[test]
    fn test_rtype_cds_from_str() {
        assert_eq!(Type::CDS, from_str::<Type>("CDS").unwrap());
    }

    #[test]
    fn test_rtype_openpgpkey_from_str() {
        assert_eq!(Type::OPENPGPKEY, from_str::<Type>("OPENPGPKEY").unwrap());
    }

    #[test]
    fn test_rtype_spf_from_str() {
        assert_eq!(Type::SPF, from_str::<Type>("SPF").unwrap());
    }

    #[test]
    fn test_rtype_uinfo_from_str() {
        assert_eq!(Type::UINFO, from_str::<Type>("UINFO").unwrap());
    }

    #[test]
    fn test_rtype_uid_from_str() {
        assert_eq!(Type::UID, from_str::<Type>("UID").unwrap());
    }

    #[test]
    fn test_rtype_gid_from_str() {
        assert_eq!(Type::GID, from_str::<Type>("GID").unwrap());
    }

    #[test]
    fn test_rtype_unspec_from_str() {
        assert_eq!(Type::UNSPEC, from_str::<Type>("UNSPEC").unwrap());
    }

    #[test]
    fn test_rtype_nid_from_str() {
        assert_eq!(Type::NID, from_str::<Type>("NID").unwrap());
    }

    #[test]
    fn test_rtype_l32_from_str() {
        assert_eq!(Type::L32, from_str::<Type>("L32").unwrap());
    }

    #[test]
    fn test_rtype_l64_from_str() {
        assert_eq!(Type::L64, from_str::<Type>("L64").unwrap());
    }

    #[test]
    fn test_rtype_lp_from_str() {
        assert_eq!(Type::LP, from_str::<Type>("LP").unwrap());
    }

    #[test]
    fn test_rtype_eui48_from_str() {
        assert_eq!(Type::EUI48, from_str::<Type>("EUI48").unwrap());
    }

    #[test]
    fn test_rtype_eui64_from_str() {
        assert_eq!(Type::EUI64, from_str::<Type>("EUI64").unwrap());
    }

    #[test]
    fn test_rtype_tkey_from_str() {
        assert_eq!(Type::TKEY, from_str::<Type>("TKEY").unwrap());
    }

    #[test]
    fn test_rtype_tsig_from_str() {
        assert_eq!(Type::TSIG, from_str::<Type>("TSIG").unwrap());
    }

    #[test]
    fn test_rtype_ixfr_from_str() {
        assert_eq!(Type::IXFR, from_str::<Type>("IXFR").unwrap());
    }

    #[test]
    fn test_rtype_axfr_from_str() {
        assert_eq!(Type::AXFR, from_str::<Type>("AXFR").unwrap());
    }

    #[test]
    fn test_rtype_mailb_from_str() {
        assert_eq!(Type::MAILB, from_str::<Type>("MAILB").unwrap());
    }

    #[test]
    fn test_rtype_maila_from_str() {
        assert_eq!(Type::MAILA, from_str::<Type>("MAILA").unwrap());
    }

    #[test]
    fn test_rtype_any_from_str() {
        assert_eq!(Type::ANY, from_str::<Type>("ANY").unwrap());
    }

    #[test]
    fn test_rtype_uri_from_str() {
        assert_eq!(Type::URI, from_str::<Type>("URI").unwrap());
    }

    #[test]
    fn test_rtype_caa_from_str() {
        assert_eq!(Type::CAA, from_str::<Type>("CAA").unwrap());
    }

    #[test]
    fn test_rtype_ta_from_str() {
        assert_eq!(Type::TA, from_str::<Type>("TA").unwrap());
    }

    #[test]
    fn test_rtype_dlv_from_str() {
        assert_eq!(Type::DLV, from_str::<Type>("DLV").unwrap());
    }

    #[test]
    fn test_rtype_reserved_from_str() {
        assert_eq!(Type::Reserved, from_str::<Type>("Reserved").unwrap());
    }

    #[test]
    fn test_rtype_none_from_raw() {
        let t: Type = FromRaw::from_raw(0).unwrap();
        assert_eq!(Type::NONE, t);
    }

    #[test]
    fn test_rtype_a_from_raw() {
        let t: Type = FromRaw::from_raw(1).unwrap();
        assert_eq!(Type::A, t);
    }

    #[test]
    fn test_rtype_ns_from_raw() {
        let t: Type = FromRaw::from_raw(2).unwrap();
        assert_eq!(Type::NS, t);
    }

    #[test]
    fn test_rtype_md_from_raw() {
        let t: Type = FromRaw::from_raw(3).unwrap();
        assert_eq!(Type::MD, t);
    }

    #[test]
    fn test_rtype_mf_from_raw() {
        let t: Type = FromRaw::from_raw(4).unwrap();
        assert_eq!(Type::MF, t);
    }

    #[test]
    fn test_rtype_cname_from_raw() {
        let t: Type = FromRaw::from_raw(5).unwrap();
        assert_eq!(Type::CNAME, t);
    }

    #[test]
    fn test_rtype_soa_from_raw() {
        let t: Type = FromRaw::from_raw(6).unwrap();
        assert_eq!(Type::SOA, t);
    }

    #[test]
    fn test_rtype_mb_from_raw() {
        let t: Type = FromRaw::from_raw(7).unwrap();
        assert_eq!(Type::MB, t);
    }

    #[test]
    fn test_rtype_mg_from_raw() {
        let t: Type = FromRaw::from_raw(8).unwrap();
        assert_eq!(Type::MG, t);
    }

    #[test]
    fn test_rtype_mr_from_raw() {
        let t: Type = FromRaw::from_raw(9).unwrap();
        assert_eq!(Type::MR, t);
    }

    #[test]
    fn test_rtype_null_from_raw() {
        let t: Type = FromRaw::from_raw(10).unwrap();
        assert_eq!(Type::NULL, t);
    }

    #[test]
    fn test_rtype_wks_from_raw() {
        let t: Type = FromRaw::from_raw(11).unwrap();
        assert_eq!(Type::WKS, t);
    }

    #[test]
    fn test_rtype_ptr_from_raw() {
        let t: Type = FromRaw::from_raw(12).unwrap();
        assert_eq!(Type::PTR, t);
    }

    #[test]
    fn test_rtype_hinfo_from_raw() {
        let t: Type = FromRaw::from_raw(13).unwrap();
        assert_eq!(Type::HINFO, t);
    }

    #[test]
    fn test_rtype_minfo_from_raw() {
        let t: Type = FromRaw::from_raw(14).unwrap();
        assert_eq!(Type::MINFO, t);
    }

    #[test]
    fn test_rtype_mx_from_raw() {
        let t: Type = FromRaw::from_raw(15).unwrap();
        assert_eq!(Type::MX, t);
    }

    #[test]
    fn test_rtype_txt_from_raw() {
        let t: Type = FromRaw::from_raw(16).unwrap();
        assert_eq!(Type::TXT, t);
    }

    #[test]
    fn test_rtype_rp_from_raw() {
        let t: Type = FromRaw::from_raw(17).unwrap();
        assert_eq!(Type::RP, t);
    }

    #[test]
    fn test_rtype_afsdb_from_raw() {
        let t: Type = FromRaw::from_raw(18).unwrap();
        assert_eq!(Type::AFSDB, t);
    }

    #[test]
    fn test_rtype_x25_from_raw() {
        let t: Type = FromRaw::from_raw(19).unwrap();
        assert_eq!(Type::X25, t);
    }

    #[test]
    fn test_rtype_isdn_from_raw() {
        let t: Type = FromRaw::from_raw(20).unwrap();
        assert_eq!(Type::ISDN, t);
    }

    #[test]
    fn test_rtype_rt_from_raw() {
        let t: Type = FromRaw::from_raw(21).unwrap();
        assert_eq!(Type::RT, t);
    }

    #[test]
    fn test_rtype_nsap_from_raw() {
        let t: Type = FromRaw::from_raw(22).unwrap();
        assert_eq!(Type::NSAP, t);
    }

    #[test]
    fn test_rtype_nsapptr_from_raw() {
        let t: Type = FromRaw::from_raw(23).unwrap();
        assert_eq!(Type::NSAPPTR, t);
    }

    #[test]
    fn test_rtype_sig_from_raw() {
        let t: Type = FromRaw::from_raw(24).unwrap();
        assert_eq!(Type::SIG, t);
    }

    #[test]
    fn test_rtype_key_from_raw() {
        let t: Type = FromRaw::from_raw(25).unwrap();
        assert_eq!(Type::KEY, t);
    }

    #[test]
    fn test_rtype_px_from_raw() {
        let t: Type = FromRaw::from_raw(26).unwrap();
        assert_eq!(Type::PX, t);
    }

    #[test]
    fn test_rtype_gpos_from_raw() {
        let t: Type = FromRaw::from_raw(27).unwrap();
        assert_eq!(Type::GPOS, t);
    }

    #[test]
    fn test_rtype_aaaa_from_raw() {
        let t: Type = FromRaw::from_raw(28).unwrap();
        assert_eq!(Type::AAAA, t);
    }

    #[test]
    fn test_rtype_loc_from_raw() {
        let t: Type = FromRaw::from_raw(29).unwrap();
        assert_eq!(Type::LOC, t);
    }

    #[test]
    fn test_rtype_nxt_from_raw() {
        let t: Type = FromRaw::from_raw(30).unwrap();
        assert_eq!(Type::NXT, t);
    }

    #[test]
    fn test_rtype_eid_from_raw() {
        let t: Type = FromRaw::from_raw(31).unwrap();
        assert_eq!(Type::EID, t);
    }

    #[test]
    fn test_rtype_nimloc_from_raw() {
        let t: Type = FromRaw::from_raw(32).unwrap();
        assert_eq!(Type::NIMLOC, t);
    }

    #[test]
    fn test_rtype_srv_from_raw() {
        let t: Type = FromRaw::from_raw(33).unwrap();
        assert_eq!(Type::SRV, t);
    }

    #[test]
    fn test_rtype_atma_from_raw() {
        let t: Type = FromRaw::from_raw(34).unwrap();
        assert_eq!(Type::ATMA, t);
    }

    #[test]
    fn test_rtype_naptr_from_raw() {
        let t: Type = FromRaw::from_raw(35).unwrap();
        assert_eq!(Type::NAPTR, t);
    }

    #[test]
    fn test_rtype_kx_from_raw() {
        let t: Type = FromRaw::from_raw(36).unwrap();
        assert_eq!(Type::KX, t);
    }

    #[test]
    fn test_rtype_cert_from_raw() {
        let t: Type = FromRaw::from_raw(37).unwrap();
        assert_eq!(Type::CERT, t);
    }

    #[test]
    fn test_rtype_dname_from_raw() {
        let t: Type = FromRaw::from_raw(39).unwrap();
        assert_eq!(Type::DNAME, t);
    }

    #[test]
    fn test_rtype_opt_from_raw() {
        let t: Type = FromRaw::from_raw(41).unwrap();
        assert_eq!(Type::OPT, t);
    }

    #[test]
    fn test_rtype_ds_from_raw() {
        let t: Type = FromRaw::from_raw(43).unwrap();
        assert_eq!(Type::DS, t);
    }

    #[test]
    fn test_rtype_sshfp_from_raw() {
        let t: Type = FromRaw::from_raw(44).unwrap();
        assert_eq!(Type::SSHFP, t);
    }

    #[test]
    fn test_rtype_ipseckey_from_raw() {
        let t: Type = FromRaw::from_raw(45).unwrap();
        assert_eq!(Type::IPSECKEY, t);
    }

    #[test]
    fn test_rtype_rrsig_from_raw() {
        let t: Type = FromRaw::from_raw(46).unwrap();
        assert_eq!(Type::RRSIG, t);
    }

    #[test]
    fn test_rtype_nsec_from_raw() {
        let t: Type = FromRaw::from_raw(47).unwrap();
        assert_eq!(Type::NSEC, t);
    }

    #[test]
    fn test_rtype_dnskey_from_raw() {
        let t: Type = FromRaw::from_raw(48).unwrap();
        assert_eq!(Type::DNSKEY, t);
    }

    #[test]
    fn test_rtype_dhcid_from_raw() {
        let t: Type = FromRaw::from_raw(49).unwrap();
        assert_eq!(Type::DHCID, t);
    }

    #[test]
    fn test_rtype_nsec3_from_raw() {
        let t: Type = FromRaw::from_raw(50).unwrap();
        assert_eq!(Type::NSEC3, t);
    }

    #[test]
    fn test_rtype_nsec3param_from_raw() {
        let t: Type = FromRaw::from_raw(51).unwrap();
        assert_eq!(Type::NSEC3PARAM, t);
    }

    #[test]
    fn test_rtype_tlsa_from_raw() {
        let t: Type = FromRaw::from_raw(52).unwrap();
        assert_eq!(Type::TLSA, t);
    }

    #[test]
    fn test_rtype_hip_from_raw() {
        let t: Type = FromRaw::from_raw(55).unwrap();
        assert_eq!(Type::HIP, t);
    }

    #[test]
    fn test_rtype_ninfo_from_raw() {
        let t: Type = FromRaw::from_raw(56).unwrap();
        assert_eq!(Type::NINFO, t);
    }

    #[test]
    fn test_rtype_rkey_from_raw() {
        let t: Type = FromRaw::from_raw(57).unwrap();
        assert_eq!(Type::RKEY, t);
    }

    #[test]
    fn test_rtype_talink_from_raw() {
        let t: Type = FromRaw::from_raw(58).unwrap();
        assert_eq!(Type::TALINK, t);
    }

    #[test]
    fn test_rtype_cds_from_raw() {
        let t: Type = FromRaw::from_raw(59).unwrap();
        assert_eq!(Type::CDS, t);
    }

    #[test]
    fn test_rtype_openpgpkey_from_raw() {
        let t: Type = FromRaw::from_raw(61).unwrap();
        assert_eq!(Type::OPENPGPKEY, t);
    }

    #[test]
    fn test_rtype_spf_from_raw() {
        let t: Type = FromRaw::from_raw(99).unwrap();
        assert_eq!(Type::SPF, t);
    }

    #[test]
    fn test_rtype_uinfo_from_raw() {
        let t: Type = FromRaw::from_raw(100).unwrap();
        assert_eq!(Type::UINFO, t);
    }

    #[test]
    fn test_rtype_uid_from_raw() {
        let t: Type = FromRaw::from_raw(101).unwrap();
        assert_eq!(Type::UID, t);
    }

    #[test]
    fn test_rtype_gid_from_raw() {
        let t: Type = FromRaw::from_raw(102).unwrap();
        assert_eq!(Type::GID, t);
    }

    #[test]
    fn test_rtype_unspec_from_raw() {
        let t: Type = FromRaw::from_raw(103).unwrap();
        assert_eq!(Type::UNSPEC, t);
    }

    #[test]
    fn test_rtype_nid_from_raw() {
        let t: Type = FromRaw::from_raw(104).unwrap();
        assert_eq!(Type::NID, t);
    }

    #[test]
    fn test_rtype_l32_from_raw() {
        let t: Type = FromRaw::from_raw(105).unwrap();
        assert_eq!(Type::L32, t);
    }

    #[test]
    fn test_rtype_l64_from_raw() {
        let t: Type = FromRaw::from_raw(106).unwrap();
        assert_eq!(Type::L64, t);
    }

    #[test]
    fn test_rtype_lp_from_raw() {
        let t: Type = FromRaw::from_raw(107).unwrap();
        assert_eq!(Type::LP, t);
    }

    #[test]
    fn test_rtype_eui48_from_raw() {
        let t: Type = FromRaw::from_raw(108).unwrap();
        assert_eq!(Type::EUI48, t);
    }

    #[test]
    fn test_rtype_eui64_from_raw() {
        let t: Type = FromRaw::from_raw(109).unwrap();
        assert_eq!(Type::EUI64, t);
    }

    #[test]
    fn test_rtype_tkey_from_raw() {
        let t: Type = FromRaw::from_raw(249).unwrap();
        assert_eq!(Type::TKEY, t);
    }

    #[test]
    fn test_rtype_tsig_from_raw() {
        let t: Type = FromRaw::from_raw(250).unwrap();
        assert_eq!(Type::TSIG, t);
    }

    #[test]
    fn test_rtype_ixfr_from_raw() {
        let t: Type = FromRaw::from_raw(251).unwrap();
        assert_eq!(Type::IXFR, t);
    }

    #[test]
    fn test_rtype_axfr_from_raw() {
        let t: Type = FromRaw::from_raw(252).unwrap();
        assert_eq!(Type::AXFR, t);
    }

    #[test]
    fn test_rtype_mailb_from_raw() {
        let t: Type = FromRaw::from_raw(253).unwrap();
        assert_eq!(Type::MAILB, t);
    }

    #[test]
    fn test_rtype_maila_from_raw() {
        let t: Type = FromRaw::from_raw(254).unwrap();
        assert_eq!(Type::MAILA, t);
    }

    #[test]
    fn test_rtype_any_from_raw() {
        let t: Type = FromRaw::from_raw(255).unwrap();
        assert_eq!(Type::ANY, t);
    }

    #[test]
    fn test_rtype_uri_from_raw() {
        let t: Type = FromRaw::from_raw(256).unwrap();
        assert_eq!(Type::URI, t);
    }

    #[test]
    fn test_rtype_caa_from_raw() {
        let t: Type = FromRaw::from_raw(257).unwrap();
        assert_eq!(Type::CAA, t);
    }

    #[test]
    fn test_rtype_ta_from_raw() {
        let t: Type = FromRaw::from_raw(32768).unwrap();
        assert_eq!(Type::TA, t);
    }

    #[test]
    fn test_rtype_dlv_from_raw() {
        let t: Type = FromRaw::from_raw(32769).unwrap();
        assert_eq!(Type::DLV, t);
    }

    #[test]
    fn test_rtype_reserved_from_raw() {
        let t: Type = FromRaw::from_raw(65535).unwrap();
        assert_eq!(Type::Reserved, t);
    }

    #[test]
    fn test_rcode_success() {
        assert_eq!(types::SUCCESS, types::rcode_from_str("SUCCESS").unwrap());
    }

    #[test]
    fn test_rcode_formerr() {
        assert_eq!(types::FORMERR, types::rcode_from_str("FORMERR").unwrap());
    }

    #[test]
    fn test_rcode_servfail() {
        assert_eq!(types::SERVFAIL, types::rcode_from_str("SERVFAIL").unwrap());
    }

    #[test]
    fn test_rcode_nameerror() {
        assert_eq!(types::NAMEERROR, types::rcode_from_str("NAMEERROR").unwrap());
    }

    #[test]
    fn test_rcode_notimpl() {
        assert_eq!(types::NOTIMPL, types::rcode_from_str("NOTIMPL").unwrap());
    }

    #[test]
    fn test_rcode_refused() {
        assert_eq!(types::REFUSED, types::rcode_from_str("REFUSED").unwrap());
    }

    #[test]
    fn test_rcode_yxdomain() {
        assert_eq!(types::YXDOMAIN, types::rcode_from_str("YXDOMAIN").unwrap());
    }

    #[test]
    fn test_rcode_yxrrset() {
        assert_eq!(types::YXRRSET, types::rcode_from_str("YXRRSET").unwrap());
    }

    #[test]
    fn test_rcode_nxrrset() {
        assert_eq!(types::NXRRSET, types::rcode_from_str("NXRRSET").unwrap());
    }

    #[test]
    fn test_rcode_notauth() {
        assert_eq!(types::NOTAUTH, types::rcode_from_str("NOTAUTH").unwrap());
    }

    #[test]
    fn test_rcode_notzone() {
        assert_eq!(types::NOTZONE, types::rcode_from_str("NOTZONE").unwrap());
    }

    #[test]
    fn test_rcode_badsig() {
        assert_eq!(types::BADSIG, types::rcode_from_str("BADSIG").unwrap());
    }

    #[test]
    fn test_rcode_badvers() {
        assert_eq!(types::BADVERS, types::rcode_from_str("BADVERS").unwrap());
    }

    #[test]
    fn test_rcode_badkey() {
        assert_eq!(types::BADKEY, types::rcode_from_str("BADKEY").unwrap());
    }

    #[test]
    fn test_rcode_badtime() {
        assert_eq!(types::BADTIME, types::rcode_from_str("BADTIME").unwrap());
    }

    #[test]
    fn test_rcode_badmode() {
        assert_eq!(types::BADMODE, types::rcode_from_str("BADMODE").unwrap());
    }

    #[test]
    fn test_rcode_badname() {
        assert_eq!(types::BADNAME, types::rcode_from_str("BADNAME").unwrap());
    }

    #[test]
    fn test_rcode_badalg() {
        assert_eq!(types::BADALG, types::rcode_from_str("BADALG").unwrap());
    }

    #[test]
    fn test_rcode_badtrunc() {
        assert_eq!(types::BADTRUNC, types::rcode_from_str("BADTRUNC").unwrap());
    }
}
