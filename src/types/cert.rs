use std::str::FromStr;

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
