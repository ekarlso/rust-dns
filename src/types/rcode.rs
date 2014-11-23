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


fn from_str(s: &str) -> u16 {
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


#[cfg(test)]
mod test {
    use types::rcode;

    #[test]
    fn test_success() {
        assert_eq!(rcode::SUCCESS, rcode::from_str("SUCCESS"));
    }

    #[test]
    fn test_formerr() {
        assert_eq!(rcode::FORMERR, rcode::from_str("FORMERR"));
    }

    #[test]
    fn test_servfail() {
        assert_eq!(rcode::SERVFAIL, rcode::from_str("SERVFAIL"));
    }

    #[test]
    fn test_nameerror() {
        assert_eq!(rcode::NAMEERROR, rcode::from_str("NAMEERROR"));
    }

    #[test]
    fn test_notimpl() {
        assert_eq!(rcode::NOTIMPL, rcode::from_str("NOTIMPL"));
    }

    #[test]
    fn test_refused() {
        assert_eq!(rcode::REFUSED, rcode::from_str("REFUSED"));
    }


    #[test]
    fn test_yxdomain() {
        assert_eq!(rcode::YXDOMAIN, rcode::from_str("YXDOMAIN"));
    }

    #[test]
    fn test_yxrrset() {
        assert_eq!(rcode::YXRRSET, rcode::from_str("YXRRSET"));
    }

    #[test]
    fn test_nxrrset() {
        assert_eq!(rcode::NXRRSET, rcode::from_str("NXRRSET"));
    }

    #[test]
    fn test_notauth() {
        assert_eq!(rcode::NOTAUTH, rcode::from_str("NOTAUTH"));
    }

    #[test]
    fn test_notzone() {
        assert_eq!(rcode::NOTZONE, rcode::from_str("NOTZONE"));
    }

    #[test]
    fn test_badsig() {
        assert_eq!(rcode::BADSIG, rcode::from_str("BADSIG"));
    }

    #[test]
    fn test_badvers() {
        assert_eq!(rcode::BADVERS, rcode::from_str("BADVERS"));
    }

    #[test]
    fn test_badkey() {
        assert_eq!(rcode::BADKEY, rcode::from_str("BADKEY"));
    }

    #[test]
    fn test_badtime() {
        assert_eq!(rcode::BADTIME, rcode::from_str("BADTIME"));
    }

    #[test]
    fn test_badmode() {
        assert_eq!(rcode::BADMODE, rcode::from_str("BADMODE"));
    }

    #[test]
    fn test_badname() {
        assert_eq!(rcode::BADNAME, rcode::from_str("BADNAME"));
    }

    #[test]
    fn test_badalg() {
        assert_eq!(rcode::BADALG, rcode::from_str("BADALG"));
    }

    #[test]
    fn test_badtrunc() {
        assert_eq!(rcode::BADTRUNC, rcode::from_str("BADTRUNC"));
    }
}