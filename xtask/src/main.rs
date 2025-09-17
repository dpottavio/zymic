use cargo_metadata::MetadataCommand;
use clap::{Args, Command, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use flate2::{Compression, GzBuilder};
use sha2::{Digest, Sha256};
use std::{
    env, fmt, fs,
    fs::File,
    io,
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process,
};
use zymic_cli::cli::Cli as ZymicCli;

use std::os::unix;

#[derive(Parser)]
#[command(name = "xtask", about = "Dev tools")]
struct XTaskCli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build zymic CLI distribution artifact.
    Dist(DistArgs),
    /// Run all tests and checks necessary to push commits.
    PreCommit,
}

#[derive(Args)]
struct DistArgs {
    #[arg(short, long, default_value_t = DistTarget::X86_64Linux)]
    target: DistTarget,
}

/// Build target options.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum DistTarget {
    #[value(name = "x86_64-linux")]
    X86_64Linux,
}

/// This type is used for software distribution artifact
/// building. Global artifact and package paths are stored globally
/// while helper functions produce the artifacts.
///
/// Directory structure:
///
///```text
///target/dist/                          <--- root_path
///    └── zymic-cli-<version>-<target>  <--- package_path
///```
///
struct Distribution {
    /// Top level directory
    root_path: PathBuf,
    /// Path to the release package.
    package_path: PathBuf,
    /// Symbolic link path to the package dir. This path omits package
    /// version.
    base_package_path: PathBuf,
    /// Full name of the package `zymic-cli-<version>-<target>`
    package_name: String,
    /// Build target.
    target: DistTarget,
}

impl Distribution {
    fn new(target: DistTarget) -> Self {
        let cmd = ZymicCli::command().name("zymic");
        let version = cmd
            .get_version()
            .expect("version")
            .split(' ')
            .next()
            .expect("version text");

        let package_name = format!("zymic-cli-{}-{}", version, target);
        let base_package_name = format!("zymic-cli-{}", target);

        let root_path = Path::new("target/dist");
        let package_path = Path::new(&root_path).join(&package_name);
        let base_package_path = Path::new(&root_path).join(&base_package_name);

        Self {
            root_path: PathBuf::from(&root_path),
            package_path,
            base_package_path,
            package_name,
            target,
        }
    }

    /// Genereate all shell man files from the CLI command type.
    fn build_man_files(&self) -> io::Result<()> {
        let man_dir = Path::new(&self.package_path).join("man");
        fs::create_dir_all(&man_dir)?;
        let mut parent_cmd_stack = Vec::default();
        let cmd = ZymicCli::command();

        build_man(&cmd, &mut parent_cmd_stack, &man_dir)?;

        Ok(())
    }

    /// Build all shell completion files from the CLI command type.
    ///
    /// Completion artifacts are written to `<package_dir>/completions`.
    fn build_all_completions(&self) -> io::Result<()> {
        let comp_path = Path::new(&self.package_path).join("completions");
        fs::create_dir_all(&comp_path)?;
        let mut cmd = ZymicCli::command();

        for s in [
            Shell::Bash,
            Shell::Elvish,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Zsh,
        ] {
            println!("shell {} {}", s, comp_path.display());
            clap_complete::generate_to(s, &mut cmd, "zymic", &comp_path)?;
        }

        Ok(())
    }

    /// Build the base package artifacts. The base package is used as the
    /// basis for other archive format, e.g., tar.gz.
    ///
    /// Example package direcotry structure:
    ///
    ///```text
    ///target/dist/
    ///    ├── SHA256SUMS.txt
    ///    ├── zymic-cli-0.1.0-x86_64-linux
    ///    │   ├── completions
    ///    │   │   ├── _zymic
    ///    │   │   ├── zymic.bash
    ///    │   │   ├── zymic.elv
    ///    │   │   ├── zymic.fish
    ///    │   │   └── _zymic.ps1
    ///    │   ├── install.sh
    ///    │   ├── LICENSE
    ///    │   ├── man
    ///    │   │   ├── zymic.1.gz
    ///    │   │   ├── zymic-dec.1.gz
    ///    │   │   ├── zymic-enc.1.gz
    ///    │   │   ├── zymic-key.1.gz
    ///    │   │   ├── zymic-key-info.1.gz
    ///    │   │   ├── zymic-key-new.1.gz
    ///    │   │   └── zymic-key-password.1.gz
    ///    │   ├── README.md
    ///    │   ├── uninstall.sh
    ///    │   └── zymic
    ///    └── zymic-cli-x86_64-linux -> zymic-cli-0.1.0-x86_64-linux
    ///```
    fn build_package(&self) -> io::Result<()> {
        self.build_man_files()?;
        self.build_all_completions()?;

        for src in [
            "README.md",
            "LICENSE",
            "xtask/scripts/install.sh",
            "xtask/scripts/uninstall.sh",
        ] {
            let src_name = Path::new(src).file_name().unwrap();
            let dest = Path::new(&self.package_path).join(src_name);
            println!("{src} -> {}", dest.display());
            fs::copy(src, &dest)?;
        }

        println!("building release target {}", self.target.name());
        let release_binary_src = build_release(self.target)?;
        let release_binary_dst = Path::new(&self.package_path).join("zymic");
        fs::copy(&release_binary_src, &release_binary_dst)?;
        println!(
            "{} -> {}",
            release_binary_src.display(),
            release_binary_dst.display()
        );

        // Set permissions.
        //
        // This is a hack. Ideally the files and their permissions
        // should be defined globally.
        #[cfg(unix)]
        walk_dir(&self.package_path, |entry| {
            use std::os::unix::fs::PermissionsExt;
            let file_type = entry.file_type()?;
            let mode = if file_type.is_dir() {
                0o755
            } else {
                let metadata = entry.metadata()?;
                let permissions = metadata.permissions();
                let mode = permissions.mode();
                // Test if this is an executable file. If so preserve
                // the execution bit.
                if mode & 0o111 > 0 { 0o755 } else { 0o644 }
            };

            fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode))?;

            Ok(())
        })?;

        // Symlink to provide a generic base name that points to the
        // versioned package distribution.
        if !self.base_package_path.exists() {
            unix::fs::symlink(&self.package_name, &self.base_package_path)?;
        }

        self.build_sha256sums()?;

        Ok(())
    }

    /// Build a tarball package archive.
    ///
    /// The tarball artifact is written to the `root_path`.
    fn build_tarball(&self) -> io::Result<()> {
        let mut files = Vec::default();
        walk_dir(&self.package_path, |f| {
            let file_type = f.file_type()?;
            if file_type.is_file() {
                files.push(f.path().clone());
            }
            Ok(())
        })?;
        // Sort the file list to ensure the tarball is deterministic.
        files.sort_by(|a, b| {
            let a_path = a.strip_prefix(&self.package_path).unwrap();
            let b_path = b.strip_prefix(&self.package_path).unwrap();
            a_path.cmp(b_path)
        });

        let tar_name = format!("{}.tar", self.package_name);
        let tar_path = Path::new(&self.root_path).join(tar_name);
        let tar_file = fs::File::create(&tar_path)?;
        let mut tar = tar::Builder::new(tar_file);
        tar.mode(tar::HeaderMode::Deterministic);
        for file in &files {
            let name = file.strip_prefix(&self.root_path).unwrap();
            tar.append_path_with_name(file, name)?;
        }
        tar.finish()?;

        let tar_file = fs::File::open(&tar_path)?;
        let mut tar_buf_reader = BufReader::new(tar_file);
        let gz_path = Path::new(&tar_path).with_extension("tar.gz");

        let gz_file = fs::File::create(&gz_path)?;
        let gz_buf_writer = BufWriter::new(gz_file);
        let mut gz_writer = GzBuilder::new()
            .mtime(0)
            .write(gz_buf_writer, Compression::best());
        io::copy(&mut tar_buf_reader, &mut gz_writer)?;
        gz_writer.finish()?;

        fs::remove_file(&tar_path)?;

        println!("{}", tar_path.display());

        Ok(())
    }

    /// Build a sha256 checksum file for each file in the `paths`
    /// list. The `dist_root_path` is stripped from the absolute path that
    /// is written to the file.
    ///
    /// The sha256 sum file is written to the `root_path`.
    fn build_sha256sums(&self) -> io::Result<()> {
        let sha_sum_file = fs::File::create(self.root_path.join("SHA256SUMS.txt"))?;
        let mut sha_sum_buf = BufWriter::new(sha_sum_file);

        walk_dir(&self.package_path, |f| {
            let file_type = f.file_type()?;
            if file_type.is_file() {
                let path = f.path();
                let file = File::open(&path)?;
                let mut file_buf = BufReader::new(file);
                let mut hash = Sha256::new();
                io::copy(&mut file_buf, &mut hash)?;
                let path = path.strip_prefix(&self.root_path).unwrap();
                writeln!(sha_sum_buf, "{:x}  {}", hash.finalize(), path.display())?;
            }
            Ok(())
        })?;

        println!("SHA256SUMS.txt");

        Ok(())
    }

    /// Build the zymic_cli .deb artifact.
    ///
    /// The .deb artifact is written to the `root_path`.
    fn build_deb(&self) -> io::Result<()> {
        let output_dir = format!("{}", self.root_path.display());

        // Hack: cargo_deb package requires the target directory to be
        // in the cli directory. Create a symlink to satisfy this.
        let target_link = Path::new("cli/target");
        if !target_link.exists() {
            unix::fs::symlink("../target", target_link)?;
        }

        // cargo deb --release -p zymic_cli -o <root dir>
        let status = process::Command::new("cargo")
            .arg("deb")
            .arg("-p")
            .arg("zymic_cli")
            .arg("-o")
            .arg(output_dir)
            .stdout(process::Stdio::inherit())
            .stderr(process::Stdio::inherit())
            .status()?;
        if !status.success() {
            return Err(io::Error::other("cargo build failure"));
        }

        fs::remove_file(target_link)?;

        Ok(())
    }
}

impl fmt::Display for DistTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DistTarget::X86_64Linux => write!(f, "x86_64-linux"),
        }
    }
}

impl DistTarget {
    /// Return the `rustup` target name this instance represents.
    fn name(&self) -> &'static str {
        match self {
            DistTarget::X86_64Linux => "x86_64-unknown-linux-musl",
        }
    }
}

/// Build a man page for a `command`.
///
/// This function operates recursively on the sub-commands of
/// `command`.
///
/// The output man pages have the following name pattern:
///```text
///<command>-<sub_command>.1.gz
///```
fn build_man(
    command: &Command,
    parent_cmd_stack: &mut Vec<Command>,
    man_path: &Path,
) -> io::Result<()> {
    let sub_cmd_name_prefix = parent_cmd_stack
        .iter()
        .map(|c| c.get_name())
        .collect::<Vec<_>>()
        .join("-");

    let man_file_name = if sub_cmd_name_prefix.is_empty() {
        format!("{}.1.gz", command.get_name())
    } else {
        format!("{}-{}.1.gz", sub_cmd_name_prefix, command.get_name())
    };
    let man_file_path = man_path.join(man_file_name);

    let file = File::create(&man_file_path)?;
    let buf_writer = BufWriter::new(file);
    let mut gz_writer = GzBuilder::new()
        .mtime(0)
        .write(buf_writer, Compression::best());

    let man = clap_mangen::Man::new(command.clone());

    man.render(&mut gz_writer)?;
    gz_writer.finish()?;

    println!("{}", man_file_path.display());

    for sub_command in command.get_subcommands() {
        parent_cmd_stack.push(command.clone());
        build_man(sub_command, parent_cmd_stack, man_path)?;
        parent_cmd_stack.pop();
    }

    Ok(())
}

/// Build a zymic_cli release target and return the path to the
/// binary.
fn build_release(target: DistTarget) -> io::Result<PathBuf> {
    let target_name = target.name();

    // cargo build --release -p zymic_cli --target <target>
    let status = process::Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("-p")
        .arg("zymic_cli")
        .arg("--target")
        .arg(target_name)
        .stdout(process::Stdio::inherit())
        .stderr(process::Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err(io::Error::other("cargo build failure"));
    }
    let bin_path = Path::new("target").join(target_name).join("release/zymic");

    Ok(bin_path)
}

/// Recursively walk the directory `root`. The `file_fn` function is
/// called for each file.
fn walk_dir<F>(root: &Path, mut file_fn: F) -> io::Result<()>
where
    F: FnMut(&fs::DirEntry) -> io::Result<()>,
{
    fn dfs<F>(dir: &Path, f: &mut F) -> io::Result<()>
    where
        F: FnMut(&fs::DirEntry) -> io::Result<()>,
    {
        for entry in fs::read_dir(dir)? {
            let e = entry?;
            if e.file_type()?.is_dir() {
                f(&e)?;
                dfs(&e.path(), f)?
            } else {
                f(&e)?
            }
        }
        Ok(())
    }
    dfs(root, &mut file_fn)?;

    Ok(())
}

/// Run all tests to validate crates before commiting to repo.
fn precommit() -> io::Result<()> {
    let test_args = [
        vec!["fmt", "--check"],
        vec!["clippy"],
        vec!["test"],
        vec!["hack", "test", "--no-run", "--feature-powerset"],
    ];
    for args in test_args {
        let status = process::Command::new("cargo")
            .args(args)
            .stdout(process::Stdio::inherit())
            .stderr(process::Stdio::inherit())
            .status()?;
        if !status.success() {
            return Err(io::Error::other("cargo fmt failure"));
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let args = XTaskCli::parse();

    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("Could not fetch cargo metadata");
    let ws_root = metadata.workspace_root;
    // Change process working dir to root workspace
    env::set_current_dir(&ws_root)?;

    match args.cmd {
        Cmd::Dist(args) => {
            let dist = Distribution::new(args.target);
            dist.build_package()?;
            dist.build_tarball()?;
            dist.build_deb()
        }
        Cmd::PreCommit => precommit(),
    }
}
