use std::io::Write;
use std::process::{Command, Stdio};
use anyhow::{ensure, Result};

fn run(cmd: &str, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    if let Some(input) = input {
        let stdin = child.stdin.as_mut();
        ensure!(stdin.is_some(), "Could not get stdin for child process");
        stdin.unwrap().write_all(input)?;
    }
    let output = child.wait_with_output()?;
    ensure!(output.status.success(), "{:?} finished with non-zero exit status {}", cmd, output.status);
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

pub(crate) fn generate_keypair() -> Result<Keypair> {
    let mut privkey = run("wg", &["genkey"], None)?.to_vec();
    let mut pubkey = run("wg", &["pubkey"], Some(&privkey))?.to_vec();

    chomp_newline(&mut privkey);
    chomp_newline(&mut pubkey);

    Ok(Keypair { privkey, pubkey })
}

#[cfg(test)]
mod tests {
    use super::chomp_newline;
    use super::generate_keypair;

    /// Does not chomp anything if there is no trailing newline
    #[test]
    fn test_chomp_newline_no_change() {
        for string in [b"hello\nworld".to_vec(), b" ".to_vec(), b"".to_vec()].iter() {
            let mut vec = string.clone();
            chomp_newline(&mut vec);
            assert_eq!(vec, *string);
        }
    }

    /// Chomps just one trailing newline
    #[test]
    fn test_chomp_newline() {
        let mut vec = b"hello\n".to_vec();
        chomp_newline(&mut vec);
        assert_eq!(vec, b"hello".to_vec());

        let mut vec = b"\n\n".to_vec();
        chomp_newline(&mut vec);
        assert_eq!(vec, b"\n".to_vec());
    }

    /// Keypair has privkey and pubkey of correct length
    #[test]
    fn test_generate_keypair() {
        let keypair = generate_keypair().unwrap();
        assert_eq!(keypair.privkey.len(), 44);
        assert_eq!(keypair.pubkey.len(), 44);
    }
}
