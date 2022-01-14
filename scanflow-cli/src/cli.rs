use memflow::prelude::v1::*;

use std::convert::TryInto;
use std::io::Write;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Instant;

use scanflow::{
    disasm::Disasm, pointer_map::PointerMap, sigmaker::Sigmaker, value_scanner::ValueScanner,
};

pub const MAX_PRINT: usize = 16;

/// Scanflow CLI context.
pub struct CliCtx<T> {
    process: T,
    value_scanner: ValueScanner,
    typename: Option<String>,
    buf_len: usize,
    disasm: Disasm,
    pointer_map: PointerMap,
}

impl<T> CliCtx<T> {
    fn new(process: T) -> Self {
        Self {
            process,
            value_scanner: Default::default(),
            typename: None,
            buf_len: 0,
            disasm: Default::default(),
            pointer_map: Default::default(),
        }
    }
}

/// Scanflow command.
pub trait CliCmd<T> {
    /// Handle the command invokation.
    ///
    /// # Arguments
    /// * `args` - string arguments that were passed.
    /// * `ctx` - reference to scanflow context.
    fn invoke(&mut self, args: &str, ctx: &mut CliCtx<T>) -> Result<()>;
    /// Get the help about this command.
    fn help(&self) -> String;
}

/// Scanflow command handler.
pub type CmdHandler<T> = fn(&str, &mut CliCtx<T>) -> Result<()>;

/// Standard scanflow command definition.
pub struct CmdDef<'a, T> {
    long: &'a str,
    short: &'a str,
    invoke: CmdHandler<T>,
    help: &'a str,
}

impl<'a, T> CmdDef<'a, T> {
    fn new(long: &'a str, short: &'a str, handle: CmdHandler<T>, help: &'a str) -> Self {
        Self {
            long,
            short,
            invoke: handle,
            help,
        }
    }
}

impl<'a, T> CliCmd<T> for CmdDef<'a, T> {
    fn invoke(&mut self, args: &str, ctx: &mut CliCtx<T>) -> Result<()> {
        (self.invoke)(args, ctx)
    }

    fn help(&self) -> String {
        format!("{} {}: {}", self.long, self.short, self.help)
    }
}

/// Run the CLI
///
/// # Arguments
///
/// * `process` - target process
pub fn run<T: Process + MemoryView + Clone>(process: T) -> Result<()> {
    let mut ctx = CliCtx::new(process);

    let mut cmds = [
        CmdDef::<T>::new("reset", "r", |_, ctx| {
            ctx.value_scanner.reset();
            ctx.disasm.reset();
            ctx.pointer_map.reset();
            ctx.typename = None;
            Ok(())
        }, "reset all context state"),
        CmdDef::<T>::new("reinterpret", "ri", |arg, ctx| {

            let mut split = arg.split_whitespace();

            let (arg, len) = (split.next().ok_or(ErrorKind::InvalidArgument)?.to_string(), split.next());

            if let Some(Type(_, size, _, _)) = TYPES.iter().filter(|Type(name, _, _, _)| name == &arg).next() {
                ctx.typename = Some(arg);

                if let Some(size) = size {
                    ctx.buf_len = *size;
                } else {
                    ctx.buf_len = len.and_then(|len| len.parse().ok()).ok_or(ErrorKind::InvalidArgument)?;
                }

                Ok(())
            } else {
                Err(ErrorKind::InvalidArgument.into())
            }

        }, "reinterpret matches as another type. Usage: {{type}} ({{unsized len}})"),
        CmdDef::<T>::new("add", "a", |arg, ctx| {
            let addr = u64::from_str_radix(arg, 16).map_err(|_| ErrorKind::InvalidArgument)?;
            ctx.value_scanner.matches_mut().push(addr.into());
            Ok(())
        }, "manually add an address to matches"),
        CmdDef::<T>::new("remove", "rm", |arg, ctx| {
            let idx = arg.parse::<usize>().map_err(|_| ErrorKind::InvalidArgument)?;
            ctx.value_scanner.matches_mut().remove(idx);
            Ok(())
        }, "remove match by index"),
        CmdDef::new("print", "p", |_, ctx| { 
            if let Some(t) = &ctx.typename {
                print_matches(&ctx.value_scanner, &mut ctx.process, ctx.buf_len, t)
            } else {
                Err(ErrorKind::Uninitialized.into())
            }
        }, "print found matches after initial scan"),
        CmdDef::new("pointer_map", "pm", |_, ctx| {
            let size_addr = ArchitectureObj::from(ctx.process.info().proc_arch).size_addr();

            ctx.pointer_map.reset();
            ctx.pointer_map.create_map(
                &mut ctx.process,
                size_addr,
            )
        }, "build a pointer map"),
        CmdDef::new("globals", "g", |_, ctx| {
            ctx.disasm.reset();
            ctx.disasm.collect_globals(&mut ctx.process)?;
            println!("Global variable references found: {:x}", ctx.disasm.map().len());
            Ok(())
        }, "find all global variables referenced by code"),
        CmdDef::new("sigmaker", "s", |args: &str, ctx| {
            if let Some(addr) = scan_fmt_some!(args, "{x}", [hex u64]) {
                match Sigmaker::find_sigs(&mut ctx.process, &ctx.disasm, addr.into()) {
                    Ok(sigs) => {
                        println!("Found signatures:");
                        for sig in sigs {
                            println!("{}", sig);
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            } else {
                Err(ErrorKind::ArgValidation.into())
            }
        }, "build a pointer map. args: {addr}"),
        CmdDef::new("offset_scan", "os", |args, ctx| {
            if let (Some(use_di), Some(lrange), Some(urange), Some(max_depth), filter_addr) =
                scan_fmt_some!(args, "{} {} {} {} {x}", String, usize, usize, usize, [hex u64])
            {
                if ctx.pointer_map.map().is_empty() {
                    let size_addr = ArchitectureObj::from(ctx.process.info().proc_arch).size_addr();
                    ctx.pointer_map.create_map(
                        &mut ctx.process,
                        size_addr
                    )?;
                }

                let start = Instant::now();

                let matches = if use_di == "y" {
                    if ctx.disasm.map().is_empty() {
                        ctx.disasm.collect_globals(&mut ctx.process)?;
                    }
                    ctx.pointer_map.find_matches_addrs(
                        (lrange, urange),
                        max_depth,
                        ctx.value_scanner.matches(),
                        ctx.disasm.globals(),
                    )
                } else {
                    ctx.pointer_map.find_matches(
                        (lrange, urange),
                        max_depth,
                        ctx.value_scanner.matches(),
                    )
                };

                println!(
                    "Matches found: {} in {:.2}ms",
                    matches.len(),
                    start.elapsed().as_secs_f64() * 1000.0
                );

                if matches.len() > MAX_PRINT {
                    println!("Printing first {} matches", MAX_PRINT);
                }
                for (m, offsets) in matches
                    .into_iter()
                        .filter(|(_, v)| {
                            if let Some(a) = filter_addr {
                                if let Some((s, _)) = v.first() {
                                    s.to_umem() == a as umem
                                } else {
                                    false
                                }
                            } else {
                                true
                            }
                        })
                .take(MAX_PRINT)
                {
                    for (start, off) in offsets.into_iter() {
                        print!("{:x} + ({}) => ", start, off);
                    }
                    println!("{:x}", m);
                }

                Ok(())
            } else {
                Err(ErrorKind::InvalidArgument.into())
            }
        }, "scan for offsets to matches. Arguments: {y/[n]} {lower range} {upper range} {max depth} ({filter})"),
        CmdDef::new("write", "wr", |args, ctx| {
            write_value(
                args,
                &ctx.typename,
                ctx.value_scanner.matches(),
                &mut ctx.process,
            )
        }, "write values to select matches. Arguments: {idx/*} {o/c} {value}"),
        ];

    loop {
        if let Some(tn) = &ctx.typename {
            print!("[{}] ", tn)
        }

        print!("scanflow@{} >> ", ctx.process.info().name);

        std::io::stdout().flush().ok();

        let line = get_line().map_err(|_| ErrorKind::UnableToReadFile)?;

        let line = line.trim();

        let mut toks = line.splitn(2, ' ');
        let (cmd, args) = (toks.next().unwrap_or(""), toks.next().unwrap_or(""));

        match cmd {
            "quit" | "q" => break,
            "help" | "h" => {
                println!("Command reference:");
                println!("quit q: quit the CLI");
                println!("help h: show this help");

                for cmd in &cmds {
                    println!("{}", cmd.help());
                }

                println!();

                println!("Anything not in this list will be interpreted as a scan input.");

                println!();

                println!("To scan memory, enter wanted data type and its value. The type is omitted in consequtive function calls.");
                println!("Available types: str, str_utf16, i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, f32, f64");

                println!();

                println!("Example:");
                println!("i64 64");
                println!("Next filtering call:");
                println!("42");
            }
            x => {
                if let Some(cmd) = cmds.iter_mut().find(|cmd| cmd.short == x || cmd.long == x) {
                    match cmd.invoke(args, &mut ctx) {
                        Ok(()) => {}
                        Err(e) => println!("{} error: {}\nHelp:\n{}", cmd.long, e, cmd.help()),
                    }
                } else {
                    if let Some((buf, t)) = parse_input(line, &ctx.typename) {
                        ctx.buf_len = buf.len();
                        ctx.value_scanner.scan_for(&mut ctx.process, &buf)?;
                        print_matches(&ctx.value_scanner, &mut ctx.process, ctx.buf_len, &t)?;
                        ctx.typename = Some(t);
                    } else {
                        println!("Invalid input! Use `help` for command reference.");
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn print_matches(
    value_scanner: &ValueScanner,
    mem: &mut impl MemoryView,
    buf_len: usize,
    typename: &str,
) -> Result<()> {
    println!("Matches found: {}", value_scanner.matches().len());

    for &m in value_scanner.matches().iter().take(MAX_PRINT) {
        let mut buf = vec![0; buf_len];
        mem.read_raw_into(m, &mut buf).data_part()?;
        println!(
            "{:x}: {}",
            m,
            print_value(&buf, typename).ok_or(ErrorKind::InvalidArgument)?
        );
    }

    Ok(())
}

pub fn get_line() -> std::io::Result<String> {
    let mut output = String::new();
    std::io::stdin().read_line(&mut output).map(|_| output)
}

pub fn async_get_line() -> Receiver<std::io::Result<String>> {
    let (tx, rx) = channel();
    thread::spawn(move || tx.send(get_line()).unwrap());
    rx
}

pub fn write_value(
    args: &str,
    typename: &Option<String>,
    matches: &[Address],
    mem: &mut impl MemoryView,
) -> Result<()> {
    if matches.is_empty() {
        return Err(ErrorKind::Uninitialized.into());
    }

    let usage: Error = ErrorKind::ArgValidation.into();
    let mut words = args.splitn(3, " ");
    let (idx, mode, value) = (
        words.next().ok_or(usage)?,
        words.next().ok_or(usage)?,
        words.next().ok_or(usage)?,
    );

    let (skip, take) = if idx == "*" {
        (0, matches.len())
    } else {
        (
            idx.parse::<usize>()
                .map_err(|_| ErrorKind::InvalidArgument)?,
            1,
        )
    };

    let gl = match mode {
        "o" => Ok(None),
        "c" => Ok(Some(async_get_line())),
        _ => Err(ErrorKind::InvalidArgument),
    }?;

    let (v, _) = parse_input(value, typename).ok_or(ErrorKind::InvalidArgument)?;

    println!("Write to matches {}-{}", skip, skip + take - 1);

    loop {
        for &m in matches.iter().skip(skip).take(take) {
            mem.write_raw(m, v.as_ref()).data_part()?;
        }

        if let Some(try_get_line) = &gl {
            if let Ok(ret) = try_get_line.try_recv() {
                if let Err(e) = ret {
                    println!("Error reading line: {}", e.to_string());
                }
                break;
            }
        } else {
            break;
        }
    }

    println!("Write done");

    Ok(())
}

type PrintFn = fn(&[u8]) -> Option<String>;
type ParseFn = fn(&str) -> Option<Box<[u8]>>;

pub struct Type(&'static str, Option<usize>, PrintFn, ParseFn);

const TYPES: &[Type] = &[
    Type(
        "str",
        None,
        |buf| Some(String::from_utf8_lossy(buf).to_string()),
        |value| Some(Box::from(value.as_bytes())),
    ),
    Type(
        "str_utf16",
        None,
        |buf| {
            let mut vec = vec![];
            for w in buf.chunks_exact(2) {
                let s = u16::from_ne_bytes(w.try_into().unwrap());
                vec.push(s);
            }
            Some(format!("{}", String::from_utf16_lossy(&vec)))
        },
        |value| {
            let mut out = vec![];
            for v in value.encode_utf16() {
                out.extend(v.to_ne_bytes().iter().copied());
            }
            Some(out.into_boxed_slice())
        },
    ),
    Type(
        "i128",
        Some(16),
        |buf| Some(format!("{}", i128::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i128>().ok()?.to_ne_bytes())),
    ),
    Type(
        "i64",
        Some(8),
        |buf| Some(format!("{}", i64::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i64>().ok()?.to_ne_bytes())),
    ),
    Type(
        "i32",
        Some(4),
        |buf| Some(format!("{}", i32::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i32>().ok()?.to_ne_bytes())),
    ),
    Type(
        "i16",
        Some(2),
        |buf| Some(format!("{}", i16::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i16>().ok()?.to_ne_bytes())),
    ),
    Type(
        "i8",
        Some(1),
        |buf| Some(format!("{}", i8::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i8>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u128",
        Some(16),
        |buf| Some(format!("{}", u128::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u128>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u64",
        Some(8),
        |buf| Some(format!("{}", u64::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u64>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u32",
        Some(4),
        |buf| Some(format!("{}", u32::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u32>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u16",
        Some(2),
        |buf| Some(format!("{}", u16::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u16>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u8",
        Some(1),
        |buf| Some(format!("{}", u8::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u8>().ok()?.to_ne_bytes())),
    ),
    Type(
        "f64",
        Some(4),
        |buf| Some(format!("{}", f64::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<f64>().ok()?.to_ne_bytes())),
    ),
    Type(
        "f32",
        Some(4),
        |buf| Some(format!("{}", f32::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<f32>().ok()?.to_ne_bytes())),
    ),
];

pub fn print_value(buf: &[u8], typename: &str) -> Option<String> {
    TYPES
        .iter()
        .filter(|Type(name, _, _, _)| name == &typename)
        .next()
        .and_then(|Type(_, _, pfn, _)| pfn(buf))
}

pub fn parse_input(input: &str, opt_typename: &Option<String>) -> Option<(Box<[u8]>, String)> {
    let (typename, value) = if let Some(t) = opt_typename {
        (t.as_str(), input)
    } else {
        let mut words = input.splitn(2, " ");
        (words.next()?, words.next()?)
    };

    let b = TYPES
        .iter()
        .filter(|Type(name, _, _, _)| name == &typename)
        .next()?
        .3(value)?;

    Some((b, typename.to_string()))
}
