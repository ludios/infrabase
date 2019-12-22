pub(crate) trait ToTableCell {
    /// Format for viewing in a table cell
    fn to_cell(&self) -> String;
}

impl ToTableCell for Option<i32> {
    fn to_cell(&self) -> String {
        match self {
            Some(port) => port.to_string(),
            None => "-".to_string(),
        }
    }
}

impl ToTableCell for Option<String> {
    fn to_cell(&self) -> String {
        match self {
            Some(s) => s.to_string(),
            None => "-".to_string(),
        }
    }
}

impl ToTableCell for Option<std::net::Ipv4Addr> {
    fn to_cell(&self) -> String {
        match self {
            Some(ipaddr) => ipaddr.to_string(),
            None => "-".to_string(),
        }
    }
}

impl ToTableCell for Option<std::net::Ipv6Addr> {
    fn to_cell(&self) -> String {
        match self {
            Some(ipaddr) => ipaddr.to_string(),
            None => "-".to_string(),
        }
    }
}
