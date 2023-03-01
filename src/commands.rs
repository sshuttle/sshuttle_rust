use std::slice::Iter;

use crate::command::{Error, ErrorKind, Line};

#[derive(Debug)]
pub struct Command {
    pub line: Line,
    pub ignore_errors: bool,
}

#[derive(Debug, Default)]
pub struct Commands(Vec<Command>);

impl Commands {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run_all(&self) -> Result<(), Error> {
        for cmd in &self.0 {
            if let Err(err) = cmd.line.run().await {
                if let ErrorKind::BadExitCode { .. } = err.kind {
                    if cmd.ignore_errors {
                        log::info!("Ignoring error: {}", err);
                    } else {
                        return Err(err);
                    }
                } else {
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> Iter<Command> {
        self.0.iter()
    }

    pub fn push(&mut self, line: Line) {
        self.0.push(Command {
            line,
            ignore_errors: false,
        });
    }

    pub fn push_ignore_errors(&mut self, line: Line) {
        self.0.push(Command {
            line,
            ignore_errors: true,
        });
    }
}

// impl Index<usize> for Commands {
//     type Output = Command;
//     fn index(&self, index: usize) -> &Command {
//         &self.0[index]
//     }
// }
