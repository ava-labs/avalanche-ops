pub fn strip_0x(addr: &str) -> &str {
    if &addr[0..2] == "0x" {
        &addr[2..]
    } else {
        addr
    }
}

pub fn prepend_0x(addr: &str) -> String {
    if &addr[0..2] == "0x" {
        String::from(addr)
    } else {
        format!("0x{}", addr)
    }
}
