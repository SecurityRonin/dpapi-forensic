//! `dpapi4n6` binary — a thin shell over the `dpapi_forensic` library (Humble
//! Object): parse args, run, print (text or JSON), and set the exit code. All
//! decisions live in the library so they are unit-tested; this file is the
//! irreducible I/O + transport shell.

use std::process::ExitCode;

use clap::Parser;
use dpapi_forensic::{render_text, Cli};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.run() {
        Ok(report) => {
            if cli.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error serializing report: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                print!("{}", render_text(&report));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("dpapi4n6: {e}");
            ExitCode::FAILURE
        }
    }
}
