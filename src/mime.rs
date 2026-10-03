//! Minimal MIME header helpers shared by the antivirus, antispam, IMAP and
//! storage code: header/body split, header unfolding, and structured-header
//! parameters (including RFC 2231 extended and continued parameters).

/// Split a message or MIME part into (headers, body) at the first empty line.
/// Without an empty line the whole input is headers and the body is empty.
pub(crate) fn split_headers_body(raw: &str) -> (&str, &str) {
    let mut pos = 0;
    for line in raw.split_inclusive('\n') {
        if line.trim_end_matches(['\r', '\n']).is_empty() {
            return (&raw[..pos], &raw[pos + line.len()..]);
        }
        pos += line.len();
    }
    (raw, "")
}

/// Parse a header block into `(lowercase name, unfolded value)` pairs, in
/// order. Continuation lines (leading space/tab) are joined with one space.
pub(crate) fn parse_headers(h: &str) -> Vec<(String, String)> {
    let mut out = parse_headers_preserving_case(h);
    for (name, _) in &mut out {
        name.make_ascii_lowercase();
    }
    out
}

/// Parse a header block into `(name, unfolded value)` pairs, in order, keeping
/// each name exactly as written (only surrounding whitespace is trimmed).
/// Continuation lines (leading space/tab) are joined with one space; lines
/// without a colon and a leading continuation line are ignored.
pub(crate) fn parse_headers_preserving_case(h: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in h.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = out.last_mut() {
                let cont = line.trim();
                if !cont.is_empty() {
                    if !last.1.is_empty() {
                        last.1.push(' ');
                    }
                    last.1.push_str(cont);
                }
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    out
}

/// Value of the first header called `name` (ASCII case-insensitive).
pub(crate) fn header<'a>(hs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    hs.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Values of every header called `name` (ASCII case-insensitive), in order.
/// Security checks use this so a second Content-Type / Content-Disposition
/// header cannot hide behind a benign first one.
pub(crate) fn header_all<'a>(hs: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    hs.iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

/// Distinct parameter names in a structured header value
/// (`type/sub; a=1; b*0=..`), lower-cased, in order of first appearance,
/// with RFC 2231 `*` / `*N` / `*N*` suffixes removed. Quote-aware: a `;` or
/// `=` inside a quoted value does not start a parameter.
pub(crate) fn header_param_names(value: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (name, _) in split_params(value) {
        let base = name.split('*').next().unwrap_or("");
        if !base.is_empty() && !names.iter().any(|n| n == base) {
            names.push(base.to_string());
        }
    }
    names
}

/// Get a parameter from a structured header value such as Content-Type or
/// Content-Disposition. Parameter names match exactly (ASCII
/// case-insensitive), so `name` never matches `filename`.
///
/// RFC 2231 forms are preferred over the plain `key=value`:
/// 1. `key*=charset'lang'pct-encoded`
/// 2. `key*0=...; key*1*=...` continuations, reassembled in index order
/// 3. `key=value` / `key="value"`
///
/// When a form occurs more than once, the first occurrence wins.
pub(crate) fn header_param(value: &str, key: &str) -> Option<String> {
    let mut forms = param_forms(value, key);
    let first = |v: &mut Vec<String>| (!v.is_empty()).then(|| v.swap_remove(0));
    first(&mut forms.extended)
        .or_else(|| first(&mut forms.continued))
        .or_else(|| first(&mut forms.plain))
}

/// Every value of parameter `key` in `value`, of every form (extended,
/// reassembled continuation, plain) in preference order, duplicates
/// included. Security checks use this so a benign value in one form or
/// occurrence cannot shadow another.
pub(crate) fn header_param_all(value: &str, key: &str) -> Vec<String> {
    let forms = param_forms(value, key);
    let mut out = forms.extended;
    out.extend(forms.continued);
    out.extend(forms.plain);
    out
}

/// All occurrences of each form of one parameter, in header order.
#[derive(Default)]
struct ParamForms {
    plain: Vec<String>,
    extended: Vec<String>,
    /// Continuations reassembled using the first occurrence of each section
    /// and, when sections repeat with different values, the last occurrence.
    continued: Vec<String>,
}

fn param_forms(value: &str, key: &str) -> ParamForms {
    let key = key.to_ascii_lowercase();
    let mut forms = ParamForms::default();
    // (index, encoded?, raw value), every occurrence in header order.
    let mut sections: Vec<(u32, bool, String)> = Vec::new();

    for (name, val) in split_params(value) {
        if name == key {
            forms.plain.push(val);
            continue;
        }
        let Some(rest) = name.strip_prefix(key.as_str()) else {
            continue;
        };
        let Some(rest) = rest.strip_prefix('*') else {
            continue;
        };
        if rest.is_empty() {
            forms.extended.push(decode_extended(&val));
            continue;
        }
        let (digits, encoded) = match rest.strip_suffix('*') {
            Some(d) => (d, true),
            None => (rest, false),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // Reject leading zeros except "0" itself (RFC 2231 section 3).
        if digits.len() > 1 && digits.starts_with('0') {
            continue;
        }
        if let Ok(idx) = digits.parse::<u32>() {
            sections.push((idx, encoded, val));
        }
    }

    if !sections.is_empty() {
        let first = reassemble(&sections, false);
        let last = reassemble(&sections, true);
        let differs = last != first;
        forms.continued.push(first);
        if differs {
            forms.continued.push(last);
        }
    }
    forms
}

/// Reassemble RFC 2231 continuation sections in index order, stopping at the
/// first gap. For a repeated index the first (or, with `last_wins`, the last)
/// occurrence is used.
fn reassemble(sections: &[(u32, bool, String)], last_wins: bool) -> String {
    let mut chosen: Vec<&(u32, bool, String)> = Vec::new();
    for sec in sections {
        match chosen.iter().position(|c| c.0 == sec.0) {
            Some(i) if last_wins => chosen[i] = sec,
            Some(_) => {}
            None => chosen.push(sec),
        }
    }
    chosen.sort_by_key(|(i, _, _)| *i);
    let mut charset: Option<String> = None;
    let mut bytes: Vec<u8> = Vec::new();
    for (expected, (idx, encoded, val)) in chosen.into_iter().enumerate() {
        if *idx as usize != expected {
            break; // gap: stop at the first missing section
        }
        if *encoded {
            let mut v = val.as_str();
            if *idx == 0 {
                if let Some((cs, rest)) = split_charset(v) {
                    charset = Some(cs.to_ascii_lowercase());
                    v = rest;
                }
            }
            bytes.extend_from_slice(&urlencoding::decode_binary(v.as_bytes()));
        } else {
            bytes.extend_from_slice(val.as_bytes());
        }
    }
    bytes_to_string(&bytes, charset.as_deref())
}

/// `charset'lang'rest` -> (charset, rest)
fn split_charset(v: &str) -> Option<(&str, &str)> {
    let (cs, rest) = v.split_once('\'')?;
    let (_lang, rest) = rest.split_once('\'')?;
    Some((cs, rest))
}

fn decode_extended(v: &str) -> String {
    let (charset, encoded) = match split_charset(v) {
        Some((cs, rest)) => (Some(cs.to_ascii_lowercase()), rest),
        None => (None, v),
    };
    let bytes = urlencoding::decode_binary(encoded.as_bytes());
    bytes_to_string(&bytes, charset.as_deref())
}

fn bytes_to_string(bytes: &[u8], charset: Option<&str>) -> String {
    match charset {
        Some("iso-8859-1" | "latin1" | "latin-1" | "us-ascii") => {
            bytes.iter().map(|&b| b as char).collect()
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Split `type/subtype; a=1; b="x;y"` into lowercase-name / unquoted-value
/// pairs (the leading token before the first `;` is skipped).
fn split_params(value: &str) -> Vec<(String, String)> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ';' if !in_quotes => segments.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    segments.push(cur);

    segments
        .iter()
        .skip(1)
        .filter_map(|seg| {
            let (name, val) = seg.split_once('=')?;
            let name = name.trim().to_ascii_lowercase();
            if name.is_empty() {
                return None;
            }
            Some((name, unquote(val.trim())))
        })
        .collect()
}

fn unquote(v: &str) -> String {
    let Some(inner) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return v.to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_parse_headers() {
        let raw = "Subject: hello\r\n  world\r\nX-A: 1\r\n\r\nbody\r\n";
        let (h, b) = split_headers_body(raw);
        assert_eq!(b, "body\r\n");
        let hs = parse_headers(h);
        assert_eq!(header(&hs, "subject"), Some("hello world"));
        assert_eq!(header(&hs, "X-A"), Some("1"));
        assert_eq!(header(&hs, "missing"), None);
        assert_eq!(split_headers_body("no body"), ("no body", ""));
    }

    #[test]
    fn preserving_case_keeps_names_and_lowercase_variant_agrees() {
        let h = "X-MiXed: a\r\n\tb\r\nSUBJECT: Re: x\r\n";
        let kept = parse_headers_preserving_case(h);
        assert_eq!(
            kept,
            vec![
                ("X-MiXed".to_string(), "a b".to_string()),
                ("SUBJECT".to_string(), "Re: x".to_string()),
            ]
        );
        let lower = parse_headers(h);
        assert_eq!(lower[0], ("x-mixed".to_string(), "a b".to_string()));
        assert_eq!(lower[1], ("subject".to_string(), "Re: x".to_string()));
    }

    #[test]
    fn plain_and_quoted_params() {
        assert_eq!(
            header_param("attachment; filename=\"a;b.exe\"", "filename"),
            Some("a;b.exe".to_string())
        );
        assert_eq!(header_param("text/plain; hostname=a", "name"), None);
        assert_eq!(
            header_param("text/plain; CHARSET=utf-8", "charset"),
            Some("utf-8".to_string())
        );
        assert_eq!(
            header_param(r#"attachment; filename="a\"b.txt""#, "filename"),
            Some("a\"b.txt".to_string())
        );
    }

    #[test]
    fn rfc2231_extended_preferred() {
        let v = "attachment; filename=\"safe.txt\"; filename*=UTF-8''r%C3%A9sum%C3%A9.exe";
        assert_eq!(header_param(v, "filename"), Some("résumé.exe".to_string()));
        assert_eq!(
            header_param_all(v, "filename"),
            vec!["résumé.exe".to_string(), "safe.txt".to_string()]
        );
        assert_eq!(
            header_param("x; name*=iso-8859-1'en'%E9t%E9", "name"),
            Some("été".to_string())
        );
    }

    #[test]
    fn rfc2231_continuations() {
        let v = "attachment; filename*1=\"part2\"; filename*0=\"part1-\"; filename*2*=%2Eexe";
        assert_eq!(
            header_param(v, "filename"),
            Some("part1-part2.exe".to_string())
        );
        let v = "attachment; filename*0*=UTF-8''%C3%A9; filename*1=\"x.exe\"; filename=\"y.txt\"";
        assert_eq!(header_param(v, "filename"), Some("éx.exe".to_string()));
        assert_eq!(
            header_param_all(v, "filename"),
            vec!["éx.exe".to_string(), "y.txt".to_string()]
        );
        // Gap stops reassembly.
        let v = "attachment; filename*0=a; filename*2=c";
        assert_eq!(header_param(v, "filename"), Some("a".to_string()));
    }

    #[test]
    fn duplicate_filename_params_are_all_reported() {
        let v = "attachment; filename=\"safe.txt\"; filename=\"evil.exe\"";
        // First wins for the plain lookup...
        assert_eq!(header_param(v, "filename"), Some("safe.txt".to_string()));
        // ...but security checks see every value.
        assert_eq!(
            header_param_all(v, "filename"),
            vec!["safe.txt".to_string(), "evil.exe".to_string()]
        );
        // Identical duplicates are kept too.
        let v = "attachment; filename=a.txt; filename=a.txt";
        assert_eq!(header_param_all(v, "filename").len(), 2);
        // Repeated extended values and repeated continuation sections.
        let v = "attachment; filename*=UTF-8''a.txt; filename*=UTF-8''b.exe";
        assert_eq!(header_param(v, "filename"), Some("a.txt".to_string()));
        assert_eq!(
            header_param_all(v, "filename"),
            vec!["a.txt".to_string(), "b.exe".to_string()]
        );
        let v = "attachment; filename*0=a; filename*1=.txt; filename*1=.exe";
        assert_eq!(header_param(v, "filename"), Some("a.txt".to_string()));
        assert_eq!(
            header_param_all(v, "filename"),
            vec!["a.txt".to_string(), "a.exe".to_string()]
        );
    }

    #[test]
    fn quoted_semicolons_in_params() {
        let v = "text/plain; name=\"x; filename=evil.exe\"; charset=\"a;b\"";
        assert_eq!(header_param_names(v), vec!["name", "charset"]);
        assert_eq!(
            header_param(v, "name"),
            Some("x; filename=evil.exe".to_string())
        );
        assert_eq!(header_param(v, "filename"), None);
        assert!(header_param_all(v, "filename").is_empty());
        assert_eq!(header_param(v, "charset"), Some("a;b".to_string()));
    }

    #[test]
    fn param_names_strip_rfc2231_suffixes() {
        let v = "attachment; FileName*0=a; filename*1*=b; name*=x; size=1";
        assert_eq!(header_param_names(v), vec!["filename", "name", "size"]);
        assert!(header_param_names("text/plain").is_empty());
    }

    #[test]
    fn header_all_returns_every_match() {
        let hs = parse_headers("Content-Type: a/b\r\nX: 1\r\ncontent-type: c/d\r\n");
        assert_eq!(header_all(&hs, "Content-Type"), vec!["a/b", "c/d"]);
        assert!(header_all(&hs, "missing").is_empty());
    }
}
