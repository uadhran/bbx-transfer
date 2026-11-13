//! bbx binary entry point. Implementation lives in the `bbx` library (src/lib.rs).
use bbx::cli::usage;
use bbx::commands::{cmd_cp, cmd_sink, cmd_source};
use std::env;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("-V") | Some("--version")) {
        println!("bbx {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.is_empty() {
        usage(1);
    }
    let cmd = args.remove(0);
    let rc = match cmd.as_str() {
        "sink" => cmd_sink(&args),
        "source" => cmd_source(&args),
        "cp" => cmd_cp(&args),
        "-h" | "--help" | "help" => {
            usage(0);
            Ok(())
        }
        _ => {
            eprintln!("unknown command: {cmd}");
            usage(1);
            Ok(())
        }
    };
    if let Err(e) = rc {
        eprintln!("bbx: {e}");
        std::process::exit(1);
    }
}
