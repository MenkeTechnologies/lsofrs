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
                csv_quote(user),
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
        Process::new(pid, 1, pid, 0, cmd.to_string(), files)
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
    fn csv_quote_comma_only_field() {
        assert_eq!(csv_quote(","), "\",\"");
    }

    #[test]
    fn csv_quote_two_commas_only() {
        assert_eq!(csv_quote(",,"), "\",,\"");
    }

    #[test]
    fn csv_quote_tab_then_comma_in_field() {
        assert_eq!(csv_quote("a\t,b"), "\"a\t,b\"");
    }

    #[test]
    fn csv_quote_lf_only_field() {
        assert_eq!(csv_quote("\n"), "\"\n\"");
    }

    #[test]
    fn csv_quote_spaces_and_commas() {
        assert_eq!(csv_quote(", ,"), "\", ,\"");
    }

    #[test]
    fn csv_quote_leading_comma_in_field() {
        assert_eq!(csv_quote(",x"), "\",x\"");
    }

    #[test]
    fn csv_quote_trailing_comma_in_field() {
        assert_eq!(csv_quote("x,"), "\"x,\"");
    }

    #[test]
    fn csv_quote_crlf_in_field() {
        assert_eq!(csv_quote("a\r\nb"), "\"a\r\nb\"");
    }

    #[test]
    fn csv_quote_cr_without_lf_unquoted() {
        assert_eq!(csv_quote("a\rb"), "a\rb");
    }

    #[test]
    fn csv_quote_with_quotes() {
        assert_eq!(csv_quote("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn csv_quote_single_double_quote_char() {
        assert_eq!(csv_quote("\""), "\"\"\"\"");
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
    fn csv_quote_carriage_return_only_unquoted() {
        assert_eq!(csv_quote("a\rb"), "a\rb");
    }

    #[test]
    fn csv_quote_utf8_without_comma_is_unquoted() {
        assert_eq!(csv_quote("café"), "café");
        assert_eq!(csv_quote("日本語"), "日本語");
    }

    #[test]
    fn csv_quote_whitespace_only_unquoted() {
        assert_eq!(csv_quote("   "), "   ");
        assert_eq!(csv_quote("\t"), "\t");
    }

    #[test]
    fn csv_quote_backslash_without_comma_unquoted() {
        assert_eq!(csv_quote(r"\"), r"\");
        assert_eq!(csv_quote(r"a\b"), r"a\b");
    }

    #[test]
    fn csv_quote_comma_and_quotes() {
        assert_eq!(csv_quote("a,\"b\",c"), "\"a,\"\"b\"\",c\"");
    }

    #[test]
    fn csv_quote_unicode_with_comma_quoted() {
        assert_eq!(csv_quote("日本語,2"), "\"日本語,2\"");
    }

    #[test]
    fn csv_quote_comma_and_emoji() {
        assert_eq!(csv_quote("ok,🎉"), "\"ok,🎉\"");
    }

    #[test]
    fn csv_quote_plain_ascii_no_comma_no_quotes() {
        assert_eq!(csv_quote("simple-cmd"), "simple-cmd");
    }

    #[test]
    fn csv_quote_zwj_sequence_without_comma_unquoted() {
        assert_eq!(csv_quote("a\u{200d}b"), "a\u{200d}b");
    }

    #[test]
    fn csv_quote_vertical_tab_without_comma_unquoted() {
        assert_eq!(csv_quote("a\u{000b}b"), "a\u{000b}b");
    }

    #[test]
    fn csv_quote_form_feed_without_comma_unquoted() {
        assert_eq!(csv_quote("a\u{000c}b"), "a\u{000c}b");
    }

    #[test]
    fn csv_quote_nul_byte_unquoted() {
        assert_eq!(csv_quote("a\u{0}b"), "a\u{0}b");
    }

    #[test]
    fn csv_quote_unicode_line_separator_unquoted() {
        assert_eq!(csv_quote("a\u{2028}b"), "a\u{2028}b");
    }

    #[test]
    fn csv_quote_line_separator_only_field_unquoted() {
        assert_eq!(csv_quote("\u{2028}"), "\u{2028}");
    }

    #[test]
    fn csv_quote_paragraph_separator_only_field_unquoted() {
        assert_eq!(csv_quote("\u{2029}"), "\u{2029}");
    }

    #[test]
    fn csv_quote_unicode_paragraph_separator_unquoted() {
        assert_eq!(csv_quote("a\u{2029}b"), "a\u{2029}b");
    }

    #[test]
    fn csv_quote_narrow_no_break_space_unquoted() {
        assert_eq!(csv_quote("a\u{202f}b"), "a\u{202f}b");
    }

    #[test]
    fn csv_quote_narrow_no_break_space_only_field_unquoted() {
        assert_eq!(csv_quote("\u{202f}"), "\u{202f}");
    }

    #[test]
    fn csv_quote_word_joiner_unquoted() {
        assert_eq!(csv_quote("a\u{2060}b"), "a\u{2060}b");
    }

    #[test]
    fn csv_quote_word_joiner_only_field_unquoted() {
        assert_eq!(csv_quote("\u{2060}"), "\u{2060}");
    }

    #[test]
    fn csv_quote_object_replacement_character_unquoted() {
        assert_eq!(csv_quote("a\u{fffc}b"), "a\u{fffc}b");
    }

    #[test]
    fn csv_quote_object_replacement_only_field_unquoted() {
        assert_eq!(csv_quote("\u{fffc}"), "\u{fffc}");
    }

    #[test]
    fn csv_quote_soft_hyphen_unquoted() {
        assert_eq!(csv_quote("a\u{00ad}b"), "a\u{00ad}b");
    }

    #[test]
    fn csv_quote_soft_hyphen_only_field_unquoted() {
        assert_eq!(csv_quote("\u{00ad}"), "\u{00ad}");
    }

    #[test]
    fn csv_quote_bom_prefix_field_unquoted() {
        assert_eq!(csv_quote("\u{feff}payload"), "\u{feff}payload");
    }

    #[test]
    fn csv_quote_fullwidth_comma_unquoted() {
        assert_eq!(csv_quote("a\u{ff0c}b"), "a\u{ff0c}b");
    }

    #[test]
    fn csv_quote_bom_only_field_unquoted() {
        assert_eq!(csv_quote("\u{feff}"), "\u{feff}");
    }

    #[test]
    fn csv_quote_embedded_double_quote_quoted() {
        assert_eq!(csv_quote("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn csv_quote_cr_only_unquoted() {
        assert_eq!(csv_quote("\r"), "\r");
    }

    #[test]
    fn csv_quote_tab_only_field_unquoted() {
        assert_eq!(csv_quote("\t"), "\t");
    }

    #[test]
    fn csv_quote_file_separator_unquoted() {
        assert_eq!(csv_quote("a\u{001c}b"), "a\u{001c}b");
    }

    #[test]
    fn csv_quote_crlf_only_field_quoted() {
        assert_eq!(csv_quote("\r\n"), "\"\r\n\"");
    }

    #[test]
    fn csv_quote_newline_only_field_is_quoted() {
        assert_eq!(csv_quote("\n"), "\"\n\"");
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

    #[test]
    fn print_csv_tab_in_field_no_quotes() {
        let procs = vec![make_proc(
            1,
            "a\tb",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        print_csv(&procs);
    }
}
