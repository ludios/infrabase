pub(crate) trait ToTableCell {
    /// Format for viewing in a table cell
    fn to_cell(&self) -> String;
}

impl ToTableCell for String {
    fn to_cell(&self) -> String {
        self.to_string()
    }
}

impl ToTableCell for &String {
    fn to_cell(&self) -> String {
        self.to_string()
    }
}

impl ToTableCell for i32 {
    fn to_cell(&self) -> String {
        self.to_string()
    }
}

impl ToTableCell for std::net::IpAddr {
    fn to_cell(&self) -> String {
        self.to_string()
    }
}

impl ToTableCell for std::net::Ipv4Addr {
    fn to_cell(&self) -> String {
        self.to_string()
    }
}

impl ToTableCell for std::net::Ipv6Addr {
    fn to_cell(&self) -> String {
        self.to_string()
    }
}

impl<T: ToTableCell> ToTableCell for Option<T> {
    fn to_cell(&self) -> String {
        match self {
            Some(s) => s.to_cell(),
            None => "-".to_string(),
        }
    }
}

impl<T: ToTableCell> ToTableCell for &Option<T> {
    fn to_cell(&self) -> String {
        match self {
            Some(s) => s.to_cell(),
            None => "-".to_string(),
        }
    }
}
