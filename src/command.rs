//! Run a binary executable
//!
//! This will run a Unix command, and keep track of stdout, stderr, and any errors.

use log::info;
use std::{
    error,
    fmt::Display,
    process::{Output, Stdio},
    result,
    str::{self, Utf8Error},
    time::{Duration, Instant},
};
use tokio::{io, process::Command};

pub fn duration_string(duration: &Duration) -> String {
    let seconds = duration.as_secs() % 60;
    let minutes = (duration.as_secs() / 60) % 60;
    let hours = (duration.as_secs() / 60) / 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

#[derive(Debug)]
pub struct Success {
    pub cmd: Line,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
}

impl Success {
    #[allow(clippy::unused_self)]
    pub fn result_line(&self) -> String {
        "Command was successful".to_string()
    }
}

impl Display for Success {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let summary = self.result_line();

        f.write_str("result: ")?;
        f.write_str(&summary)?;
        f.write_str("\n")?;

        f.write_str("command: ")?;
        f.write_str(&self.cmd.to_string())?;
        f.write_str("\n")?;

        f.write_str("duration: ")?;
        f.write_str(&duration_string(&self.duration))?;
        f.write_str("\n")?;

        f.write_str("stdout:\n")?;
        f.write_str(&self.stdout)?;
        f.write_str("\n")?;

        f.write_str("stderr:\n")?;
        f.write_str(&self.stderr)?;
        f.write_str("\n")?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Error {
    pub cmd: Line,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub exit_code: i32,
    pub kind: ErrorKind,
}

#[derive(Debug)]
pub enum ErrorKind {
    BadExitCode,
    FailedToStart { err: std::io::Error },
    Utf8Error { err: Utf8Error },
}

impl From<Utf8Error> for ErrorKind {
    fn from(err: Utf8Error) -> Self {
        Self::Utf8Error { err }
    }
}

impl Error {
    pub fn result_line(&self) -> String {
        match &self.kind {
            ErrorKind::BadExitCode {} => format!("Bad Exit code {}", self.exit_code),
            ErrorKind::FailedToStart { err } => format!("Failed to start: {err}"),
            ErrorKind::Utf8Error { err } => format!("UTF-8 error: {err}"),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let summary = self.result_line();

        f.write_str("result: ")?;
        f.write_str(&summary)?;
        f.write_str("\n")?;

        f.write_str("command: ")?;
        f.write_str(&self.cmd.to_string())?;
        f.write_str("\n")?;

        f.write_str("duration: ")?;
        f.write_str(&duration_string(&self.duration))?;
        f.write_str("\n")?;

        f.write_str("stdout:\n")?;
        f.write_str(&self.stdout)?;
        f.write_str("\n")?;

        f.write_str("stderr:\n")?;
        f.write_str(&self.stderr)?;
        f.write_str("\n")?;

        Ok(())
    }
}

impl error::Error for Error {}

pub type Result = result::Result<Success, Error>;

#[derive(Clone, Eq, PartialEq)]
pub struct Line(pub String, pub Vec<String>);

fn get_exit_code(output: &result::Result<Output, io::Error>) -> i32 {
    output
        .as_ref()
        .map_or(-1, |output| output.status.code().unwrap_or(-1))
}

fn get_stdin_out(
    output: &result::Result<Output, io::Error>,
) -> result::Result<(String, String), ErrorKind> {
    if let Ok(output) = &output {
        let stdin = str::from_utf8(&output.stdout)?;
        let stderr = str::from_utf8(&output.stderr)?;
        Ok((stdin.to_string(), stderr.to_string()))
    } else {
        Ok((String::new(), String::new()))
    }
}

impl Line {
    pub fn new(cmd: impl Into<String>, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let cmd = cmd.into();
        let args = args.into_iter().map(std::convert::Into::into).collect();
        Self(cmd, args)
    }

    pub async fn run(&self) -> Result {
        let start = Instant::now();
        info!("Running command: {self}");

        let Self(cmd, args) = &self;
        let output = Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        let exit_code = get_exit_code(&output);
        let duration = start.elapsed();

        let (stdout, stderr) = match get_stdin_out(&output) {
            Ok(output) => output,
            Err(err) => {
                return Err(Error {
                    cmd: self.clone(),
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code,
                    duration,
                    kind: err,
                })
            }
        };

        let kind = match output {
            Err(err) => Err(ErrorKind::FailedToStart { err }),
            Ok(output) => {
                if output.status.success() {
                    Ok(())
                } else {
                    Err(ErrorKind::BadExitCode {})
                }
            }
        };

        match kind {
            Ok(()) => Ok(Success {
                cmd: self.clone(),
                stdout,
                stderr,
                duration,
            }),
            Err(kind) => Err(Error {
                cmd: self.clone(),
                stdout,
                stderr,
                exit_code,
                duration,
                kind,
            }),
        }
    }
}

impl Display for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        for arg in &self.1 {
            write!(f, " {arg}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommandLine(\"{}", self.0)?;
        for arg in &self.1 {
            write!(f, " {arg}")?;
        }
        write!(f, "\")")?;
        Ok(())
    }
}
