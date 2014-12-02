use std::default::Default;

use std::io::BufferedReader;
use std::io::File;
use std::io::net::ip::{IpAddr,Port,SocketAddr};
use std::str::from_str;


use regex::Regex;

const DEFAULT_PORT: Port = 53;
const DEFAULT_SERVER: &'static str= "127.0.0.1";
const DEFAULT_ATTEMPTS: int = 3;


fn get_default_server() -> SocketAddr {
    let addr: IpAddr = from_str::<IpAddr>(DEFAULT_SERVER).unwrap();
    SocketAddr { ip: addr, port: DEFAULT_PORT }
}


// A client config
pub struct ClientConfig {
    pub bind: Option<SocketAddr>,
    pub servers: Vec<SocketAddr>,
    pub search: Vec<String>,
    pub attempts: int
}

// Provide default config
impl Default for ClientConfig {
    fn default() -> ClientConfig {
        let mut servers = Vec::new();
        servers.push(get_default_server());

        ClientConfig {
            bind: None,
            servers: servers,
            search: Vec::new(),
            attempts: DEFAULT_ATTEMPTS
        }
    }
}

// Provide some methods for constructing / reading a config
impl ClientConfig {
    pub fn from_resolvconf(resolvconf: &str) -> ClientConfig {
        let p = &Path::new(resolvconf);
        let mut file = BufferedReader::new(File::open(p));

        let mut servers = Vec::new();
        let mut search = Vec::new();

        let opt_re = match Regex::new(r"^(domain|nameserver|search|options)\s+?(\S+)$") {
            Ok(v) => v,
            Err(err) => panic!("{}", err)
        };

        for line in file.lines() {
            match line {
                Ok(resolv_val) => {
                    let data = resolv_val.replace("\n", "");
                    let fields = data.split_str(" ").collect::<Vec<_>>();

                    if fields.len() < 1 {
                        continue
                    }

                    match fields[0] {
                        "nameserver" => {
                            match from_str::<IpAddr>(fields[1]) {
                                Some(addr)  => {
                                    let saddr = SocketAddr {
                                        ip: addr,
                                        port: DEFAULT_PORT
                                    };

                                    servers.push(saddr); },
                                None        => {}
                            }
                        },
                        "domain" => {
                            search.push(String::from_str(fields[1]));
                        }
                        _ => {}
                    }
                },
                Err(e) => {}
            }
        }

        ClientConfig {
            servers: servers,
            search: search,
            ..Default::default()
        }
    }
}