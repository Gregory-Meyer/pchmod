// Copyright (c) 2019 Gregory Meyer
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice (including the next
// paragraph) shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

extern crate clap;
extern crate env_logger;
extern crate log;
extern crate rayon;

use std::{
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process,
    str::FromStr,
};

use clap::{crate_authors, crate_description, crate_name, crate_version, values_t, App, Arg};
use log::{debug, error, warn};
use rayon::prelude::*;

fn main() {
    let retc = start();

    if retc != 0 {
        process::exit(retc);
    }
}

const MODE_HELP: &'static str =
"A comma-separed sequence of modes that can be symbolic or octal.
Octal modes must be 4 digits or shorter. Missing digits are assumed to be zero.
Symbolic modes must be of the form '[<CLASS>*]<OPERATOR><PERMISSION>*.'

<CLASS> is one of '[ugoa]'. 'u' changes permissions for the owner, 'g'
changes permissions for the owning group, 'o' changes permissions for all
other users. 'a' is equivalent to specifying 'ugo'. If <CLASS> is not
provided, it is assumed to be 'a'.

<OPERATOR> is one of '[+\\-=]' and specifies how permissions are modified for
the specified class(es) of users. '+' adds permissions, '-' removes
permissions, and '=' sets permissions exactly.

<PERMISSION> is one of '[rwxst]' and specifies what permissions are to be
modified. 'r' corresponds to read, 'w' to write, and 'x' to execute. If set,
's' will set the uid and gid of that file to the current user's uid and gid
when executed. If set, 't' will set the sticky bit of that file or directory.
Only the file's/parent directory's owner or root user can rename or delete
sticky files.
";

fn start() -> i32 {
    env_logger::init();

    let matches = App::new(crate_name!())
        .about(crate_description!())
        .author(crate_authors!("\n"))
        .version(crate_version!())
        .arg(
            Arg::with_name("recursive")
                .short("R")
                .long("recursive")
                .help("Change mode of files and directories recursively"),
        )
        .arg(
            Arg::with_name("mode")
                .required(true)
                .index(1)
                .takes_value(true)
                .value_name("MODE")
                .help("Mode to set files and directories to")
                .long_help(MODE_HELP),
        )
        .arg(
            Arg::with_name("pathnames")
                .help("Pathnames of files or directories to modify mode of")
                .required(true)
                .multiple(true)
                .index(2)
                .takes_value(true)
                .value_name("PATHNAME"),
        )
        .get_matches();

    let paths = match values_t!(matches, "pathnames", PathBuf) {
        Ok(p) => p,
        Err(e) => {
            error!("couldn't get arg pathnames: {}", e);

            return 1;
        }
    };

    let mode_strs = matches.value_of("mode").unwrap().split(',');
    let mut modes = Vec::new();

    for s in mode_strs {
        match s.parse::<Mode>() {
            Ok(m) => modes.push(m),
            Err(e) => {
                error!("couldn't parse '{}' as a mode: {}", s, e);

                return 1;
            }
        }
    }

    debug!("modes: {:?}", modes);

    if matches.is_present("recursive") {
        paths
            .par_iter()
            .for_each(|path| chmod_recursive(path, &modes));
    } else {
        paths.par_iter().for_each(|path| chmod(path, &modes));
    }

    0
}

fn chmod_recursive(path: &Path, modes: &[Mode]) {
    chmod(path, modes);

    if !path.is_dir() {
        return;
    }

    let entries: Vec<_> = match path.read_dir() {
        Ok(i) => i.collect(),
        Err(e) => {
            warn!("couldn't read directory '{}': {}", path.display(), e);

            return;
        }
    };

    entries.par_iter().for_each(|entry| {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    "couldn't read directory entry of '{}': {}",
                    path.display(),
                    e
                );

                return;
            }
        };

        chmod_recursive(&entry.path(), modes);
    });
}

fn chmod(path: &Path, modes: &[Mode]) {
    let perm = match path.metadata() {
        Ok(m) => m.permissions().mode() & 0o7777,
        Err(e) => {
            warn!("couldn't get permissions of '{}': {}", path.display(), e);

            return;
        }
    };

    let new_perm = modes.iter().fold(perm, |p, m| m.mutate(p));

    if let Err(e) = fs::set_permissions(path, Permissions::from_mode(new_perm)) {
        warn!(
            "couldn't set permissions of '{}' to {:04o}: {}",
            path.display(),
            new_perm,
            e
        );
    } else {
        debug!(
            "changed permissions of '{}' from {:04o} to {:04o}",
            path.display(),
            perm,
            new_perm
        );
    }
}

#[derive(Copy, Clone)]
enum Mode {
    Add(u32),
    Remove(u32),
    Set { mask: u32, to_set: u32 },
}

impl Mode {
    fn mutate(&self, perm: u32) -> u32 {
        match self {
            Mode::Add(m) => perm | m,
            Mode::Remove(m) => perm & m,
            Mode::Set { mask, to_set } => (perm & mask) | to_set,
        }
    }
}

impl FromStr for Mode {
    type Err = ParseModeError;

    fn from_str(s: &str) -> Result<Mode, ParseModeError> {
        if let Ok(m) = u32::from_str_radix(s, 8) {
            if m & 0o7777 != m {
                return Err(ParseModeError::OctalOutOfRange(m));
            }

            return Ok(Mode::Set { mask: 0, to_set: m });
        }

        let mut state = ParserState::References;

        let mut user_ref = false;
        let mut group_ref = false;
        let mut other_ref = false;
        let mut write = false;
        let mut read = false;
        let mut execute = false;
        let mut setuid_gid = false;
        let mut sticky = false;
        let mut operator = None;

        for (i, c) in s.chars().enumerate() {
            match state {
                ParserState::References => match c {
                    'u' => user_ref = true,
                    'g' => group_ref = true,
                    'o' => other_ref = true,
                    'a' => {
                        user_ref = true;
                        group_ref = true;
                        other_ref = true;
                    }
                    '+' | '-' | '=' => {
                        state = ParserState::Modes;

                        if i == 0 {
                            user_ref = true;
                            group_ref = true;
                            other_ref = true;
                        }

                        match c {
                            '+' => operator = Some(Operator::Add),
                            '-' => operator = Some(Operator::Remove),
                            '=' => operator = Some(Operator::Set),
                            _ => (),
                        }
                    }
                    _ => return Err(ParseModeError::InvalidReferenceCharacter(c, i)),
                },
                ParserState::Modes => match c {
                    'r' => read = true,
                    'w' => write = true,
                    'x' => execute = true,
                    's' => setuid_gid = true,
                    't' => sticky = true,
                    _ => return Err(ParseModeError::InvalidModeCharacter(c, i)),
                },
            }
        }

        let mut bits = 0;

        if setuid_gid {
            bits |= 0o6000;
        }

        if sticky {
            bits |= 0o1000;
        }

        if user_ref && read {
            bits |= 0o0400;
        }

        if user_ref && write {
            bits |= 0o0200;
        }

        if user_ref && execute {
            bits |= 0o0100;
        }

        if group_ref && read {
            bits |= 0o0040;
        }

        if group_ref && write {
            bits |= 0o0020;
        }

        if group_ref && execute {
            bits |= 0o0010;
        }

        if other_ref && read {
            bits |= 0o0004;
        }

        if other_ref && write {
            bits |= 0o0002;
        }

        if other_ref && execute {
            bits |= 0o0001;
        }

        return match operator.unwrap() {
            Operator::Add => Ok(Mode::Add(bits)),
            Operator::Remove => Ok(Mode::Remove(!bits & 0o7777)),
            Operator::Set => {
                let mut mask = 0;

                if !setuid_gid {
                    mask |= 0o6000;
                }

                if !sticky {
                    mask |= 0o1000;
                }

                if !user_ref {
                    mask |= 0o0700;
                }

                if !group_ref {
                    mask |= 0o0070;
                }

                if !other_ref {
                    mask |= 0o0007;
                }

                Ok(Mode::Set { mask, to_set: bits })
            }
        };
    }
}

impl Debug for Mode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Mode::Add(m) => write!(f, "Add({:04o})", m),
            Mode::Remove(m) => write!(f, "Remove({:04o})", m),
            Mode::Set { mask, to_set } => {
                write!(f, "Set {{ mask: {:04o}, to_set: {:04o} }}", mask, to_set)
            }
        }
    }
}

#[derive(Debug)]
enum ParseModeError {
    OctalOutOfRange(u32),
    InvalidReferenceCharacter(char, usize),
    InvalidModeCharacter(char, usize),
}

impl Error for ParseModeError {}

impl Display for ParseModeError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ParseModeError::OctalOutOfRange(x) => write!(f, "{} is not a valid mode", x),
            ParseModeError::InvalidReferenceCharacter(c, i) => {
                write!(f, "invalid reference character '{}' at char index {}", c, i)
            }
            ParseModeError::InvalidModeCharacter(c, i) => {
                write!(f, "invalid mode character '{}' at char index {}", c, i)
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum ParserState {
    References,
    Modes,
}

#[derive(Copy, Clone, Debug)]
enum Operator {
    Add,
    Remove,
    Set,
}
