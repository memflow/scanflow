# scanflow

[![Crates.io](https://img.shields.io/crates/v/scanflow.svg)](https://crates.io/crates/scanflow)
[![Crates.io](https://img.shields.io/crates/v/scanflow-cli.svg)](https://crates.io/crates/scanflow-cli)
[![API Docs](https://docs.rs/scanflow/badge.svg)](https://docs.rs/scanflow)
[![Build and test](https://github.com/h33p/scanflow/actions/workflows/build.yml/badge.svg)](https://github.com/h33p/scanflow/actions/workflows/build.yml)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## A comprehensive memory scanning library

scanflow boasts a feature set similar to the likes of CheatEngine, with a simple command line interface. Utilizing [memflow](https://crates.io/memlfow), scanflow works in a wide range of situations - from virtual machines, to dedicated DMA hardware. While it's focused around the CLI, it can also be used as a standalone library, easy to integrate to other memflow projects. With performance being at its forefront, scanflow should be able to achieve revolutionary memory scan speeds.

## Setting up

1. Install the CLI:

```
cargo install scanflow-cli
```

2. Optionally enable ptrace for the binary (for use with qemu):

```
sudo setcap 'CAP_SYS_PTRACE=ep' ~/.cargo/bin/scanflow-cli
```

3. Set up connectors using [memflowup](https://github.com/memflow/memflowup)

4. Enjoy:

```
scanflow-cli -c qemu_procfs -p svchost.exe
```

## Background

This tool came to be as a result of my YouTube series detailing memflow and various memory scanning techniques. If you wish to learn more, check out the [memflow-applied playlist](https://www.youtube.com/playlist?list=PLrC4R7zDrxB17iWCy9eEdCaluCR3Bkn8q).

[memflow-applied](https://github.com/h33p/memflow-applied) repo is also available with snapshots of different stages of development.
