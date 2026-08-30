# lsof

The `lsof` command name for [lsofrs](https://github.com/MenkeTechnologies/lsofrs) — a
modern, high-performance `lsof` implementation in Rust.

```sh
cargo install lsof
```

Installs an `lsof` binary that runs lsofrs. Every flag, output mode, and the
7-tab TUI are the lsofrs ones: this crate is a single `fn main()` over
`lsofrs::run()`, so the two can never diverge.

Install the tool under its own names instead with:

```sh
cargo install lsofrs   # installs `lsofrs` and `lsf`
```

Documentation, flags, and screenshots: <https://menketechnologies.github.io/lsofrs/>

## License

MIT
