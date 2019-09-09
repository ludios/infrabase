macro_rules! unwrap_or_else {
    ($opt:expr, $else:expr) => {
        match $opt {
            Some(x) => x,
            None => $else
        }
    };
}

macro_rules! ok_or_else {
    ($opt:expr, $else:expr) => {
        match $opt {
            Some(x) => Some(x),
            None => $else
        }
    };
}
