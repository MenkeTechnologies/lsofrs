//! CSV export for pipelines/spreadsheets

use std::io::{self, Write};

use crate::types::*;

/// Quote a CSV field if it contains commas, quotes, or newlines.
/// Embedded quotes are doubled per RFC 4180.
fn csv_quote(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        let escaped = field.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        field.to_string()
    }
}

pub fn print_csv(procs: &[Process]) {
    let out = io::stdout();
    let mut out = out.lock();

    let _ = writeln!(out, "COMMAND,PID,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME");

    for p in procs {
        let user = p.username();
        for f in &p.files {
            let _ = writeln!(
                out,
                "{},{},{},{},{},{},{},{},{}",
                csv_quote(&p.command),
                p.pid,
                csv_quote(&user),
                csv_quote(&f.fd.with_access(f.access)),
                csv_quote(f.file_type.as_str()),
                csv_quote(&f.device_str()),
                csv_quote(&f.size_or_offset_str()),
                csv_quote(&f.node_str()),
                csv_quote(&f.full_name()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: i32, cmd: &str, files: Vec<OpenFile>) -> Process {
        Process {
            pid,
            ppid: 1,
            pgid: pid,
            uid: 0,
            command: cmd.to_string(),
            files,
            sel_flags: 0,
            sel_state: 0,
        }
    }

    fn make_file(fd: i32, ft: FileType, name: &str) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: ft,
            name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn csv_quote_no_special() {
        assert_eq!(csv_quote("hello"), "hello");
    }

    #[test]
    fn csv_quote_with_comma() {
        assert_eq!(csv_quote("hello,world"), "\"hello,world\"");
    }

    #[test]
    fn csv_quote_with_quotes() {
        assert_eq!(csv_quote("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn csv_quote_with_newline() {
        assert_eq!(csv_quote("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn csv_quote_empty() {
        assert_eq!(csv_quote(""), "");
    }

    #[test]
    fn csv_quote_tab_only_unquoted() {
        assert_eq!(csv_quote("a\tb"), "a\tb");
    }

    #[test]
    fn csv_quote_comma_and_quotes() {
        assert_eq!(csv_quote("a,\"b\",c"), "\"a,\"\"b\"\",c\"");
    }

    #[test]
    fn print_csv_empty_no_panic() {
        print_csv(&[]);
    }

    #[test]
    fn print_csv_with_data_no_panic() {
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/foo")],
        )];
        print_csv(&procs);
    }

    #[test]
    fn print_csv_special_chars_no_panic() {
        let procs = vec![make_proc(
            42,
            "my,cmd",
            vec![make_file(3, FileType::Reg, "/path/with \"quotes\"")],
        )];
        print_csv(&procs);
    }

    #[test]
    fn print_csv_multiple_files_no_panic() {
        let procs = vec![make_proc(
            42,
            "test",
            vec![
                make_file(0, FileType::Chr, "/dev/null"),
                make_file(1, FileType::Chr, "/dev/tty"),
                make_file(3, FileType::Reg, "/tmp/data.txt"),
            ],
        )];
        print_csv(&procs);
    }

    #[test]
    fn print_csv_multiple_processes_no_panic() {
        let procs = vec![
            make_proc(1, "init", vec![make_file(0, FileType::Chr, "/dev/null")]),
            make_proc(2, "bash", vec![make_file(3, FileType::Reg, "/tmp/x")]),
        ];
        print_csv(&procs);
    }

    #[test]
    fn print_csv_utf8_command_and_path_no_panic() {
        let procs = vec![make_proc(
            42,
            "プロセス",
            vec![make_file(1, FileType::Reg, "/tmp/文件")],
        )];
        print_csv(&procs);
    }

    #[test]
    fn print_csv_empty_command_string_no_panic() {
        let procs = vec![make_proc(
            42,
            "",
            vec![make_file(0, FileType::Chr, "/dev/null")],
        )];
        print_csv(&procs);
    }

    #[test]
    fn print_csv_pipe_in_name_field_no_panic() {
        let procs = vec![make_proc(
            1,
            "writer",
            vec![make_file(1, FileType::Pipe, "pipe:[12345]")],
        )];
        print_csv(&procs);
    }
}
