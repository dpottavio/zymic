// SPDX-License-Identifier: MIT

//! CLI Integration Tests

#[cfg(test)]
mod cli_integ_tests {
    use rexpect::{process::wait::WaitStatus, session::spawn_command, spawn, spawn_bash};

    use std::{
        env, fs, io,
        io::{Read, Write},
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicU32, Ordering},
    };

    /// Timeout for cli spawned sessions in MS.
    const SESSION_TIMEOUT_MS: u64 = 5_000;

    static NEXT_FILE_ID: AtomicU32 = AtomicU32::new(0);

    struct TmpDir {
        path: PathBuf,
    }

    impl TmpDir {
        fn new(path: &str) -> Self {
            fs::create_dir_all(path).unwrap();
            Self {
                path: PathBuf::from(path),
            }
        }

        fn mkdir(&self, path: &Path) -> PathBuf {
            let mut p = PathBuf::from(&self.path);
            p.push(path);
            fs::create_dir_all(&p).unwrap();
            p
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap()
        }
    }

    const CLI_PATH: &str = env!("CARGO_BIN_EXE_zymic");
    const DEFAULT_PASSWORD: &str = "foo";

    /// Create a plain text file. Each call to this function creates a
    /// new plain text file with the same data.
    fn create_plaintxt(working_dir: &Path) -> PathBuf {
        let mut path = PathBuf::from(&working_dir);
        let file_name = format!("plaintxt-{}", NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed));
        path.push(file_name);
        let mut file_1 = fs::File::create(&path).unwrap();
        file_1.write_all(b"Hello 12345\n").unwrap();
        file_1.flush().unwrap();
        path
    }

    /// Create a new key using the CLI.
    fn cli_new_key(working_dir: &Path) -> PathBuf {
        let mut path = PathBuf::from(&working_dir);
        path.push("key");

        let cmd = format!("{} key new -k {} -a min", CLI_PATH, path.display());

        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_string("re-enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));
        path
    }

    /// Encrypt a file at 'plaintxt_path` using the CLI. The path to
    /// the ciphertxt is returned.
    fn cli_encrypt(working_dir: &Path, key_path: &Path, plaintxt_path: &Path) -> PathBuf {
        let mut ciphertxt_path = PathBuf::from(working_dir);
        ciphertxt_path.push("ciphertxt.zym");

        let cmd = format!(
            "{} enc -k {} -o {} {}",
            CLI_PATH,
            key_path.display(),
            ciphertxt_path.display(),
            plaintxt_path.display()
        );

        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));

        ciphertxt_path
    }

    /// Encrypt a file at 'plaintxt_path` using the CLI. This version
    /// of the CLI wrapper function does not specify the output file
    /// and relies on the default output which is the plaintxt_path
    /// plus the .zym extension.
    fn cli_encrypt_default_out(key_path: &Path, plaintxt_path: &Path) -> PathBuf {
        let cmd = format!(
            "{} enc -k {} {}",
            CLI_PATH,
            key_path.display(),
            plaintxt_path.display()
        );

        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));
        let mut cipher_txt = PathBuf::from(plaintxt_path);
        cipher_txt.set_extension("zym");
        cipher_txt
    }

    /// Encrypt a file at 'plaintxt_path` using the CLI. This version
    /// of the CLI wrapper function does not specify the output file
    /// and relies on the default output which is the plaintxt_path
    /// plus the .zym extension. If the output file exists, it is
    /// overwirtten.
    fn cli_encrypt_default_out_force(key_path: &Path, plaintxt_path: &Path) -> PathBuf {
        let cmd = format!(
            "{} enc -f -k {} {}",
            CLI_PATH,
            key_path.display(),
            plaintxt_path.display()
        );

        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));
        let mut cipher_txt = PathBuf::from(plaintxt_path);
        cipher_txt.set_extension("zym");
        cipher_txt
    }

    /// Encrypt a file at 'plaintxt_path' using the CLI. This version
    /// of the CLI wrapper using stdin to read the plaintxt and stdout
    /// to write the cipher text. No file arguments are provided to
    /// the CLI.
    #[cfg(unix)]
    fn cli_encrypt_stdin_out(working_dir: &Path, key_path: &Path, plaintxt_path: &Path) -> PathBuf {
        let mut ciphertxt_path = PathBuf::from(working_dir);
        ciphertxt_path.push("ciphertxt");
        let cmd = format!(
            "{} enc -k {} < {} > {}",
            CLI_PATH,
            key_path.display(),
            plaintxt_path.display(),
            ciphertxt_path.display()
        );
        cli_crypt_bash(&cmd);
        ciphertxt_path
    }

    /// Encrypt a file at 'plaintxt_path' using the CLI. This version
    /// of the CLI wrapper using stdin to read the plaintxt and stdout
    /// to write the cipher text. The '-' dash arguments are provided
    /// to signal to the CLI to use stdin and stdout.
    #[cfg(unix)]
    fn cli_encrypt_stdin_out_dash(
        working_dir: &Path,
        key_path: &Path,
        plaintxt_path: &Path,
    ) -> PathBuf {
        let mut ciphertxt_path = PathBuf::from(working_dir);
        ciphertxt_path.push("ciphertxt");
        let cmd = format!(
            "cat {} | {} enc -k {} -o - - > {}",
            plaintxt_path.display(),
            CLI_PATH,
            key_path.display(),
            ciphertxt_path.display()
        );
        cli_crypt_bash(&cmd);
        ciphertxt_path
    }

    /// Decrypt a file at 'ciphertxt_path' using the CLI. This version
    /// of the CLI wrapper using stdin to read the plaintxt and stdout
    /// to write the cipher text. No file arguments are provided to
    /// the CLI.
    #[cfg(unix)]
    fn cli_decrypt_stdin_out(
        working_dir: &Path,
        key_path: &Path,
        ciphertxt_path: &Path,
    ) -> PathBuf {
        let mut plaintxt_path = PathBuf::from(working_dir);
        plaintxt_path.push("plaintxt_decoded");
        let cmd = format!(
            "{} dec -k {} < {} > {}",
            CLI_PATH,
            key_path.display(),
            ciphertxt_path.display(),
            plaintxt_path.display(),
        );
        cli_crypt_bash(&cmd);
        plaintxt_path
    }

    /// Decrypt a file at 'ciphertxt_path' using the CLI. This version
    /// of the CLI wrapper using stdin to read the plaintxt and stdout
    /// to write the cipher text. The '-' dash arguments are provided
    /// to signal to the CLI to use stdin and stdout.
    #[cfg(unix)]
    fn cli_decrypt_stdin_out_dash(
        working_dir: &Path,
        key_path: &Path,
        ciphertxt_path: &Path,
    ) -> PathBuf {
        let mut plaintxt_path = PathBuf::from(working_dir);
        plaintxt_path.push("plaintxt_decoded");
        let cmd = format!(
            "cat {} | {} dec -k {} -o - - > {}",
            ciphertxt_path.display(),
            CLI_PATH,
            key_path.display(),
            plaintxt_path.display()
        );
        cli_crypt_bash(&cmd);
        plaintxt_path
    }

    /// Helper function for spawning the CLI in a bash shell
    /// environment.
    #[cfg(unix)]
    fn cli_crypt_bash(cmd: &str) {
        let mut session = spawn_bash(Some(SESSION_TIMEOUT_MS)).unwrap();
        session.execute(cmd, "enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.wait_for_prompt().unwrap();
        session.send_control('d').unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));
    }

    /// Decrypt a file using the CLI. The path to the plaintxt output
    /// is returned.
    fn cli_decrypt(working_dir: &Path, key_path: &Path, ciphertxt_path: &Path) -> PathBuf {
        let mut plaintxt_path = PathBuf::from(working_dir);
        let file_name = format!(
            "plaintxt_decoded-{}",
            NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed)
        );
        plaintxt_path.push(file_name);

        let cmd = format!(
            "{} dec -k {} -o {} {}",
            CLI_PATH,
            key_path.display(),
            plaintxt_path.display(),
            ciphertxt_path.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));

        plaintxt_path
    }

    /// Decrypt a file at 'plaintxt_path` using the CLI. This version
    /// of the CLI wrapper function does not specify the output file
    /// and relies on the default output which is the ciphertxt_path
    /// minus the .zym. extension.
    fn cli_decrypt_default_out(key_path: &Path, ciphertxt_path: &Path) {
        let cmd = format!(
            "{} dec -k {}  {}",
            CLI_PATH,
            key_path.display(),
            ciphertxt_path.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));
    }

    /// Decrypt a file at 'plaintxt_path` using the CLI. This version
    /// of the CLI wrapper function does not specify the output file
    /// and relies on the default output which is the ciphertxt_path
    /// minus the .zym. extension. If the plain text file already
    /// exists, it is overwritten.
    fn cli_decrypt_default_out_force(key_path: &Path, ciphertxt_path: &Path) {
        let cmd = format!(
            "{} dec -f -k {}  {}",
            CLI_PATH,
            key_path.display(),
            ciphertxt_path.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));
    }

    /// Change the password of a key file at 'key_path' using the CLI.
    fn cli_change_password(key_path: &Path, password: &str) {
        let cmd = format!("{} key password -k {}", CLI_PATH, key_path.display());

        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_string("enter new key password:").unwrap();
        session.send_line(password).unwrap();
        session.exp_string("re-enter key password:").unwrap();
        session.send_line(password).unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));
    }

    /// Check the integrity of a key file at 'key_path' using the CLI.
    fn cli_check_key(key_path: &Path, password: &str) {
        let cmd = format!("{} key check -k {}", CLI_PATH, key_path.display());

        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(password).unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 0)));
    }

    /// Assert that two files are identical.
    fn file_compare(f1: &Path, f2: &Path) -> bool {
        if fs::metadata(f1).unwrap().len() != fs::metadata(f2).unwrap().len() {
            return false;
        }
        let f1 = io::BufReader::new(fs::File::open(f1).unwrap());
        let f2 = io::BufReader::new(fs::File::open(f2).unwrap());
        f1.bytes()
            .zip(f2.bytes())
            .all(|(b1, b2)| b1.unwrap() == b2.unwrap())
    }

    /// Test that a new key can be created.
    #[test]
    fn new_key() {
        let tmp_dir = TmpDir::new("new_key");
        let _ = cli_new_key(&tmp_dir.path);
    }

    /// Test that a file can be encrypted and decrypted.
    #[test]
    fn crypt() {
        let tmp_dir = TmpDir::new("crypt");
        let key_path = cli_new_key(&tmp_dir.path);
        let plaintxt_path = create_plaintxt(&tmp_dir.path);
        let ciphertxt_path = cli_encrypt(&tmp_dir.path, &key_path, &plaintxt_path);
        let plaintxt_path_2 = cli_decrypt(&tmp_dir.path, &key_path, &ciphertxt_path);
        assert!(file_compare(&plaintxt_path, &plaintxt_path_2));
    }

    /// Test that a file can be encrypted and decrypted using the
    /// default output.
    #[test]
    fn crypt_default_out() {
        let tmp_dir = TmpDir::new("crypt_default_out");
        let key_path = cli_new_key(&tmp_dir.path);
        let plaintxt_path = create_plaintxt(&tmp_dir.path);

        // Expecting the cipher txt to have the .zym extension for the
        // default output.
        let mut ciphertxt_path = plaintxt_path.clone();
        ciphertxt_path.set_extension("zym");

        cli_encrypt_default_out(&key_path, &plaintxt_path);
        assert!(ciphertxt_path.exists());

        // Remove the original plain txt file to ensure it gets
        // generated as the default output of the decryption.
        fs::remove_file(&plaintxt_path).unwrap();

        cli_decrypt_default_out(&key_path, &ciphertxt_path);
        assert!(plaintxt_path.exists());

        // Generate the same plaintxt with a different path and
        // compare it against the decryption result.
        let plaintxt_path_expected = create_plaintxt(&tmp_dir.path);
        assert!(file_compare(&plaintxt_path_expected, &plaintxt_path));
    }

    /// Test that a file can be encrypted and decrypted using stdin and
    /// stdout.
    #[cfg(unix)]
    #[test]
    fn crypt_stdin_stdout() {
        let tmp_dir = TmpDir::new("crypt_stdin_stdout");
        let key_path = cli_new_key(&tmp_dir.path);
        let plaintxt_expected_path = create_plaintxt(&tmp_dir.path);
        let ciphertxt_path =
            cli_encrypt_stdin_out(&tmp_dir.path, &key_path, &plaintxt_expected_path);
        let plaintxt_path = cli_decrypt_stdin_out(&tmp_dir.path, &key_path, &ciphertxt_path);
        assert!(file_compare(&plaintxt_expected_path, &plaintxt_path));
    }

    /// Test that a file can be encrypted and decrpted using stdin and
    /// stdout by passing the '-' dash argument.
    #[cfg(unix)]
    #[test]
    fn crypt_stdin_out_dash() {
        let tmp_dir = TmpDir::new("crypt_stdin_out_dash");
        let key_path = cli_new_key(&tmp_dir.path);
        let plaintxt_expected_path = create_plaintxt(&tmp_dir.path);
        let ciphertxt_path =
            cli_encrypt_stdin_out_dash(&tmp_dir.path, &key_path, &plaintxt_expected_path);
        let plaintxt_path = cli_decrypt_stdin_out_dash(&tmp_dir.path, &key_path, &ciphertxt_path);
        assert!(file_compare(&plaintxt_expected_path, &plaintxt_path));
    }

    /// Test that the password for a key can be changed.
    #[test]
    fn key_password_change() {
        let tmp_dir = TmpDir::new("key_password_change");
        let new_password = "1234567890";
        let key_path = cli_new_key(&tmp_dir.path);
        cli_change_password(&key_path, new_password);
        cli_check_key(&key_path, new_password);
    }

    /// Test that the ZYMIC_DIR config variable can set to change the
    /// default location for keys.
    #[test]
    fn config_dir() {
        let tmp_dir = TmpDir::new("config_dir");

        let mut cmd = Command::new(CLI_PATH);
        cmd.arg("key");
        cmd.arg("new");
        cmd.env("ZYMIC_DIR", format!("{}", tmp_dir.path.display()));
        let mut session = spawn_command(cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_string("re-enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_eof().unwrap();

        let mut key_path = PathBuf::from(&tmp_dir.path);
        key_path.push("zymic_key.json");
        assert!(key_path.exists());
    }

    /// Test the key info command.
    #[test]
    fn key_info() {
        let tmp_dir = TmpDir::new("key_info");
        let key_path = cli_new_key(&tmp_dir.path);
        let cmd = format!("{} key info -k {}", CLI_PATH, key_path.display());

        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("path:").unwrap();
        session.exp_string("id:").unwrap();
        session.exp_string("date:").unwrap();
        session.exp_string("argon:").unwrap();
        session.exp_eof().unwrap();
    }

    /// Force overwrite file decrypt
    #[test]
    fn force_file_encrypt() {
        let tmp_dir = TmpDir::new("force_file_encrypt");
        let key_path = cli_new_key(&tmp_dir.path);
        let plain_txt = create_plaintxt(&tmp_dir.path);

        let cipher_txt = cli_encrypt_default_out(&key_path, &plain_txt);
        let cipher_txt_cpy = PathBuf::from(format!("{}-copy", cipher_txt.display()));
        fs::copy(cipher_txt.clone(), cipher_txt_cpy.clone()).unwrap();

        cli_encrypt_default_out_force(&key_path, &plain_txt);

        assert!(!file_compare(&cipher_txt, &cipher_txt_cpy));
    }

    /// Test that a file is not overwritten without force flag.
    #[test]
    fn no_force_file_encrypt() {
        let tmp_dir = TmpDir::new("no_force_file_encrypt");
        let key_path = cli_new_key(&tmp_dir.path);
        let plain_txt = create_plaintxt(&tmp_dir.path);

        let cipher_txt = cli_encrypt_default_out(&key_path, &plain_txt);
        let cipher_txt_cpy = PathBuf::from(format!("{}-copy", cipher_txt.display()));
        fs::copy(cipher_txt.clone(), cipher_txt_cpy.clone()).unwrap();

        let cmd = format!(
            "{} enc -k {} {}",
            CLI_PATH,
            key_path.display(),
            plain_txt.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_string("error: File exists").unwrap();
        session.exp_eof().unwrap();

        // There should be no change in the file.
        assert!(file_compare(&cipher_txt, &cipher_txt_cpy));
    }

    /// Force overwrite file decrypt
    #[test]
    fn force_file_decrypt() {
        let tmp_dir = TmpDir::new("force_file_decrypt");
        let key_path = cli_new_key(&tmp_dir.path);
        let plain_txt = create_plaintxt(&tmp_dir.path);
        let plain_txt_cpy = PathBuf::from(format!("{}-copy", plain_txt.display()));
        fs::copy(plain_txt.clone(), plain_txt_cpy.clone()).unwrap();

        let cipher_txt = cli_encrypt_default_out(&key_path, &plain_txt);

        // trucate the original plain txt to 0
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&plain_txt)
            .unwrap();

        cli_decrypt_default_out_force(&key_path, &cipher_txt);

        // The plain text file should be restored.
        assert!(file_compare(&plain_txt, &plain_txt_cpy));
    }

    /// Test that a file is not overwritten without force flag.
    #[test]
    fn no_force_file_decrypt() {
        let tmp_dir = TmpDir::new("no_force_file_decrypt");
        let key_path = cli_new_key(&tmp_dir.path);
        let plain_txt = create_plaintxt(&tmp_dir.path);
        let plain_txt_cpy = PathBuf::from(format!("{}-copy", plain_txt.display()));
        fs::copy(plain_txt.clone(), plain_txt_cpy.clone()).unwrap();

        let cipher_txt = cli_encrypt_default_out(&key_path, &plain_txt);

        // trucate the original plain txt to 0
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&plain_txt)
            .unwrap();

        let cmd = format!(
            "{} dec -k {} {}",
            CLI_PATH,
            key_path.display(),
            cipher_txt.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_string("error: File exists").unwrap();
        session.exp_eof().unwrap();

        // Since the overwrite was aborted, the files should not be equal.
        assert!(!file_compare(&plain_txt, &plain_txt_cpy));
    }

    /// Negative test that a key cannot be overwritten by a new key.
    #[test]
    fn err_new_key_exists() {
        let tmp_dir = TmpDir::new("err_new_key_exists");
        let key_path = cli_new_key(&tmp_dir.path);

        let cmd = format!("{} key new -k {}", CLI_PATH, key_path.display());
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session
            .exp_string(&format!(
                "error: key '{}' already exists",
                key_path.display()
            ))
            .unwrap();
        session.exp_eof().unwrap();
    }

    /// Negative test that a directory cannot be encrypted.
    #[test]
    fn err_dir_not_supported() {
        let tmp_dir = TmpDir::new("err_dir_not_supported");
        let key_path = cli_new_key(&tmp_dir.path);
        let dir = tmp_dir.mkdir(Path::new("foo"));

        let cmd = format!(
            "{} enc -k {} {}",
            CLI_PATH,
            key_path.display(),
            dir.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session
            .exp_string("error: directory encryption is not supported")
            .unwrap();
        session.exp_eof().unwrap();
    }

    /// Negative test that a directory cannot be the output
    /// destination.
    #[test]
    fn err_dir_output() {
        let tmp_dir = TmpDir::new("err_dir_output");
        let key_path = cli_new_key(&tmp_dir.path);
        let plaintxt = create_plaintxt(&tmp_dir.path);
        let dir = tmp_dir.mkdir(Path::new("foo"));

        let cmd = format!(
            "{} enc -k {} -o {} {}",
            CLI_PATH,
            key_path.display(),
            dir.display(),
            plaintxt.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session
            .exp_string("error: output file is a directory")
            .unwrap();
        session.exp_eof().unwrap();
    }

    /// Negative test that the wrong key password produces an
    /// authentication failure.
    #[test]
    fn err_auth_failure() {
        let tmp_dir = TmpDir::new("err_auth_failure");
        let key_path = cli_new_key(&tmp_dir.path);
        let plaintxt_path = create_plaintxt(&tmp_dir.path);

        let cmd = format!(
            "{} enc -k {} {}",
            CLI_PATH,
            key_path.display(),
            plaintxt_path.display(),
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session
            .send_line(&format!("{DEFAULT_PASSWORD}-bad"))
            .unwrap();
        session.exp_string("error: authentication failure").unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 1)));
    }

    /// Negative test that a new key password must be different from
    /// the old password.
    #[test]
    fn err_key_password_change() {
        let tmp_dir = TmpDir::new("err_key_password_change");
        let key_path = cli_new_key(&tmp_dir.path);
        let cmd = format!("{} key password -k {}", CLI_PATH, key_path.display());

        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_string("enter new key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session
            .exp_string("error: new password is the same as old password")
            .unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 1)));
    }

    /// Negative test that a key password must be entered twice.
    #[test]
    fn err_key_password_not_match() {
        let tmp_dir = TmpDir::new("err_key_password_not_match");
        let mut key_path = PathBuf::from(&tmp_dir.path);
        key_path.push("key");
        let cmd = format!("{} key new -k {}", CLI_PATH, key_path.display());

        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session.exp_string("re-enter key password:").unwrap();
        session
            .send_line(&format!("{DEFAULT_PASSWORD}-bad"))
            .unwrap();
        session.exp_string("error: passwords do not match").unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 1)));
    }

    /// Negative test of decrypting a file without a .zym extension.
    #[test]
    fn err_dec_no_extension() {
        let tmp_dir = TmpDir::new("err_dec_no_extension");
        let key_path = cli_new_key(&tmp_dir.path);
        let plaintxt_path = create_plaintxt(&tmp_dir.path);
        let mut ciphertxt_path = cli_encrypt(&tmp_dir.path, &key_path, &plaintxt_path);
        // remove .zym extestion
        ciphertxt_path.set_extension("");

        let cmd = format!(
            "{} dec -k {} {}",
            CLI_PATH,
            key_path.display(),
            ciphertxt_path.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session
            .exp_string("error: input file extension is not valid, only .zym is supported")
            .unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 1)));
    }

    /// Negative test of decrypting a file with the wrong extension.
    #[test]
    fn err_dec_bad_extension() {
        let tmp_dir = TmpDir::new("err_dec_bad_extension");
        let key_path = cli_new_key(&tmp_dir.path);
        let plaintxt_path = create_plaintxt(&tmp_dir.path);
        let mut ciphertxt_path = cli_encrypt(&tmp_dir.path, &key_path, &plaintxt_path);
        // remove .zym extestion
        ciphertxt_path.set_extension("foo");

        let cmd = format!(
            "{} dec -k {} {}",
            CLI_PATH,
            key_path.display(),
            ciphertxt_path.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session.exp_string("enter key password:").unwrap();
        session.send_line(DEFAULT_PASSWORD).unwrap();
        session
            .exp_string("error: input file extension is not valid, only .zym is supported")
            .unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 1)));
    }

    /// Negative test of key file not found.
    #[test]
    fn err_enc_key_file_not_found() {
        let tmp_dir = TmpDir::new("err_enc_key_file_not_found");
        let plaintxt_path = create_plaintxt(&tmp_dir.path);

        let cmd = format!(
            "{} enc -k /bad/path/1/2/3 {}",
            CLI_PATH,
            plaintxt_path.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session
            .exp_string("error: key file could not be found")
            .unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 1)));
    }

    /// Negative test of key file not found.
    #[test]
    fn err_dec_key_file_not_found() {
        let tmp_dir = TmpDir::new("err_dec_key_file_not_found");
        let plaintxt_path = create_plaintxt(&tmp_dir.path);

        let cmd = format!(
            "{} dec -k /bad/path/1/2/3 {}",
            CLI_PATH,
            plaintxt_path.display()
        );
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session
            .exp_string("error: key file could not be found")
            .unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 1)));
    }

    /// Negative test of key file not found.
    #[test]
    fn err_show_key_file_not_found() {
        let cmd = format!("{} key info -k /bad/path/1/2/3", CLI_PATH,);
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session
            .exp_string("error: key file could not be found")
            .unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 1)));
    }

    /// Negative test of key file not found.
    #[test]
    fn err_check_key_file_not_found() {
        let cmd = format!("{} key check -k /bad/path/1/2/3", CLI_PATH,);
        let mut session = spawn(&cmd, Some(SESSION_TIMEOUT_MS)).unwrap();
        session
            .exp_string("error: key file could not be found")
            .unwrap();
        session.exp_eof().unwrap();
        let status = session.process.exit().unwrap();
        assert!(matches!(status, WaitStatus::Exited(_, 1)));
    }
}
