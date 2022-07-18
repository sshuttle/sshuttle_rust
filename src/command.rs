use std::{
    error::Error,
    fmt::Display,
    process::Stdio,
    str,
    time::{Duration, Instant},
};
use tokio::process::Command;

use crate::duration::duration_string;

pub struct CommandSuccess {
    pub cmd: CommandLine,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
}

#[derive(Debug)]
pub enum CommandError {
    BadExitCode {
        cmd: CommandLine,
        stdout: String,
        stderr: String,
        rc: i32,
        duration: Duration,
    },
    FailedToStart {
        cmd: CommandLine,
        error: std::io::Error,
    },
}

impl Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::BadExitCode {
                cmd,
                stdout,
                stderr,
                rc,
                duration,
            } => {
                write!(
                    f,
                    "Command: {}\nBad exit code: {}\nstdout: {}\nstderr: {}\nduration: {}",
                    cmd,
                    rc,
                    stdout,
                    stderr,
                    duration_string(duration)
                )
            }
            CommandError::FailedToStart { cmd, error } => {
                write!(f, "Command: {}\nFailed to start: {}", cmd, error)
            }
        }
    }
}

impl Error for CommandError {}

#[derive(Clone, Eq, PartialEq)]
pub struct CommandLine(pub String, pub Vec<String>);

impl CommandLine {
    pub async fn run(&self) -> Result<CommandSuccess, CommandError> {
        let start = Instant::now();

        let CommandLine(cmd, args) = &self;
        let output = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        use CommandError::*;
        match output {
            Err(err) => Err(FailedToStart {
                cmd: self.clone(),
                error: err,
            }),
            Ok(output) => {
                let stdout = str::from_utf8(&output.stdout).unwrap();
                let stderr = str::from_utf8(&output.stderr).unwrap();

                if output.status.success() {
                    Ok(CommandSuccess {
                        cmd: self.clone(),
                        stdout: stdout.to_string(),
                        stderr: stderr.to_string(),
                        duration: start.elapsed(),
                    })
                } else {
                    Err(BadExitCode {
                        cmd: self.clone(),
                        stdout: stdout.to_string(),
                        stderr: stderr.to_string(),
                        rc: output.status.code().unwrap(),
                        duration: start.elapsed(),
                    })
                }
            }
        }
    }
}

impl Display for CommandLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        for arg in &self.1 {
            write!(f, " {}", arg)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for CommandLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommandLine(\"{}", self.0)?;
        for arg in &self.1 {
            write!(f, " {}", arg)?;
        }
        write!(f, "\")")?;
        Ok(())
    }
}
