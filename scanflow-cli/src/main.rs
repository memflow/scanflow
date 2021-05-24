use memflow::connector::{inventory::ConnectorInventory, ConnectorArgs};

use clap::*;
use log::Level;

use memflow_win32::win32::{Kernel, Win32Process};
use memflow_win32::Result;

use simplelog::{Config, TermLogger, TerminalMode};

#[macro_use]
extern crate scan_fmt;

mod cli;

fn main() -> Result<()> {
    let (target, conn, args, level) = parse_args()?;

    TermLogger::init(level.to_level_filter(), Config::default(), TerminalMode::Mixed).unwrap();

    let inventory = unsafe { ConnectorInventory::scan() };
    let connector = unsafe { inventory.create_connector(&conn, &args)? };

    let mut kernel = Kernel::builder(connector).build_default_caches().build()?;

    let process_info = kernel.process_info(&target)?;

    let process = Win32Process::with_kernel(kernel, process_info);

    cli::run(process)
}

fn parse_args() -> Result<(String, String, ConnectorArgs, log::Level)> {
    let matches = App::new("scanflow-cli")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("verbose").short("v").multiple(true))
        .arg(
            Arg::with_name("connector")
                .long("connector")
                .short("c")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("conn-args")
                .long("conn-args")
                .short("x")
                .takes_value(true)
                .default_value(""),
        )
        .arg(
            Arg::with_name("program")
                .long("program")
                .short("p")
                .takes_value(true)
                .required(true)
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
        matches.value_of("connector").unwrap_or("").into(),
        ConnectorArgs::parse(matches.value_of("conn-args").unwrap())?,
        level,
    ))
}
