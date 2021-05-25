use clap::*;
use log::Level;

use memflow::prelude::v1::{Result, *};

use simplelog::{Config, TermLogger, TerminalMode};

#[macro_use]
extern crate scan_fmt;

mod cli;

fn main() -> Result<()> {
    let (target, conn, args, os, os_args, level) = parse_args()?;

    TermLogger::init(
        level.to_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
    )
    .unwrap();

    let inventory = Inventory::scan();

    let os = match conn {
        Some(conn) => inventory
            .builder()
            .connector(&conn)
            .args(args)
            .os(&os)
            .args(os_args)
            .build(),
        None => inventory.builder().os(&os).args(os_args).build(),
    }?;

    let process = os.into_process_by_name(&target)?;

    cli::run(process)
}

fn parse_args() -> Result<(String, Option<String>, Args, String, Args, log::Level)> {
    let matches = App::new("scanflow-cli")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("verbose").short("v").multiple(true))
        .arg(
            Arg::with_name("connector")
                .long("connector")
                .short("c")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("conn-args")
                .long("conn-args")
                .short("x")
                .takes_value(true)
                .default_value(""),
        )
        .arg(
            Arg::with_name("os")
                .long("os")
                .short("o")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("os-args")
                .long("os-args")
                .short("y")
                .takes_value(true)
                .default_value(""),
        )
        .arg(
            Arg::with_name("program")
                .long("program")
                .short("p")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    // set log level
    let level = match matches.occurrences_of("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        4 => Level::Trace,
        _ => Level::Trace,
    };

    Ok((
        matches.value_of("program").unwrap_or("").into(),
        matches.value_of("connector").map(|s| s.into()),
        Args::parse(matches.value_of("conn-args").unwrap())?,
        matches.value_of("os").unwrap_or("").into(),
        Args::parse(matches.value_of("os-args").unwrap())?,
        level,
    ))
}
