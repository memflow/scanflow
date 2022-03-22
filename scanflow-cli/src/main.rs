use clap::*;
use log::Level;

use memflow::prelude::v1::{Result, *};

use simplelog::{Config, TermLogger, TerminalMode};

#[macro_use]
extern crate scan_fmt;

mod cli;

fn main() -> Result<()> {
    let matches = parse_args();
    let (chain, target, elevate, level) = extract_args(&matches)?;

    if elevate {
        #[cfg(unix)]
        sudo::escalate_if_needed().expect("failed to elevate privileges");
        #[cfg(windows)]
        log::warn!("elevation not supported on windows!");
    }

    TermLogger::init(
        level.to_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
    )
    .unwrap();

    let inventory = Inventory::scan();

    let os = inventory.builder().os_chain(chain).build()?;

    let process = os.into_process_by_name(&target)?;

    cli::run(process)
}

fn parse_args() -> ArgMatches {
    Command::new("scanflow-cli")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::new("verbose").short('v').multiple_occurrences(true))
        .arg(
            Arg::new("connector")
                .long("connector")
                .short('c')
                .takes_value(true)
                .required(false)
                .multiple_occurrences(true),
        )
        .arg(
            Arg::new("os")
                .long("os")
                .short('o')
                .takes_value(true)
                .required(true)
                .multiple_occurrences(true),
        )
        .arg(
            Arg::new("elevate")
                .long("elevate")
                .short('e')
                .required(false),
        )
        .arg(Arg::new("program").takes_value(true).required(true))
        .get_matches()
}

fn extract_args(matches: &ArgMatches) -> Result<(OsChain, &str, bool, log::Level)> {
    // set log level
    let level = match matches.occurrences_of("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        4 => Level::Trace,
        _ => Level::Trace,
    };

    let conn_iter = matches
        .indices_of("connector")
        .zip(matches.values_of("connector"))
        .map(|(a, b)| a.zip(b))
        .into_iter()
        .flatten();

    let os_iter = matches
        .indices_of("os")
        .zip(matches.values_of("os"))
        .map(|(a, b)| a.zip(b))
        .into_iter()
        .flatten();

    Ok((
        OsChain::new(conn_iter, os_iter)?,
        matches.value_of("program").unwrap_or(""),
        matches.occurrences_of("elevate") > 0,
        level,
    ))
}
