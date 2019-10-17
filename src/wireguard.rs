use std::io::Write;
use std::process::{Command, Stdio};
use snafu::ResultExt;
use super::Error;
use super::Io;

fn run(cmd: &str, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn().context(Io)?;

    if let Some(input) = input {
        let stdin = child.stdin.as_mut().ok_or(Error::NoStdin)?;
        stdin.write_all(input).context(Io)?;
    }
    let output = child.wait_with_output().context(Io)?;
    if !output.status.success() {
        return Err(Error::NonZeroExit);
    }

    Ok(output.stdout)
}

pub(crate) struct Keypair {
    pub privkey: Vec<u8>,
    pub pubkey: Vec<u8>,
}

fn chomp_newline(vec: &mut Vec<u8>) {
    if let Some(b'\n') = vec.last() {
        vec.pop();
    }
}

pub(crate) fn generate_keypair() -> Result<Keypair, Error> {
    let mut privkey = run("wg", &["genkey"], None)?.to_vec();
    let mut pubkey = run("wg", &["pubkey"], Some(&privkey))?.to_vec();

    chomp_newline(&mut privkey);
    chomp_newline(&mut pubkey);

    Ok(Keypair { privkey, pubkey })
}
