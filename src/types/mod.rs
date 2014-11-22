use std::str::FromStr;

pub enum Types {
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

// impl FromStr for Types {};

pub enum Class {
    INET = 1,
    CSNET = 2,
    CHAOS = 3,
    HESIOD = 4,
    NONE = 254,
    ANY = 255
}

pub enum Rcode {
    Success = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    YXDomain = 6,
    YXRrset = 7,
    NXRrset = 8,
    NotAuth = 9,
    NotZone = 10,
    BadSig = 16,  // this
    // BadVers = 16, // ... and this  have the same discriminant
    BadKey = 17,
    BadTime = 18,
    BadMode = 19,
    BadName = 20,
    BadAlg = 21,
    BadTrunc = 22,
}

pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

pub enum Certs {
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

#[cfg(test)]
mod test {
    #[test]
    fn test_test () {
    //    assert_eq!(tupes::from_str("A"), 1);
    }
}
