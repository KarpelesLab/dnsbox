//! `dig`-style presentation of a whole message: the `Display` impl of
//! [`Message`], shared with the owned message type.
//!
//! The layout is that of BIND 9's `dig` (the de-facto standard text form of
//! a DNS message), checked line by line against `dig` 9.18 on the interop
//! corpus (`tests/dig_display.rs`):
//!
//! ```text
//! ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 38925
//! ;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
//!
//! ;; OPT PSEUDOSECTION:
//! ; EDNS: version: 0, flags:; udp: 1232
//! ; EDE: 9 (DNSKEY Missing): (no SEP matching the DS found for dnssec-failed.org.)
//! ; NSID: 6e 72 74 30 39 ("nrt09")
//! ;; QUESTION SECTION:
//! ;dnssec-failed.org.             IN      A
//!
//! ```
//!
//! - the header line carries the opcode, the full status (the header RCODE
//!   combined with the OPT extended RCODE, RFC 6891 §6.1.3) and the ID;
//! - the flags line lists the set header flags (RFC 1035 §4.1.1, RFC 4035
//!   §3.2; the reserved Z bit as `MBZ: 0x4`) and the four section counts
//!   (named ZONE / PREREQ / UPDATE / ADDITIONAL for UPDATE messages, RFC
//!   2136 §2), followed by `dig`'s warnings (a response with RD but no RA,
//!   bytes after the last record);
//! - the OPT record is shown as the `OPT PSEUDOSECTION` (RFC 6891 §6.1):
//!   the EDNS header, then one line per option, in `dig`'s format for the
//!   options it knows (NSID, CLIENT-SUBNET, EXPIRE, COOKIE, TCP KEEPALIVE,
//!   PAD, KEY-TAG, EDE, CLIENT-TAG, SERVER-TAG, LLQ), the presentation
//!   value for the other options dnsbox decodes (`; CHAIN: example.`), and
//!   `OPT=<code>:` with the data in hex otherwise;
//! - records use BIND's column layout (tab stops of 8, TTL at column 24,
//!   class at 32, type at 40, RDATA at 48) and zone-file RDATA (long base64
//!   and hex fields are not split into chunks the way BIND does);
//! - TSIG records (RFC 8945 §4.2) and SIG(0) records (RFC 2931 §3: a SIG
//!   covering type 0) of the additional section are shown in the
//!   `TSIG PSEUDOSECTION` / `SIG0 PSEUDOSECTION`.
//!
//! Nothing here allocates, and every walk over the message is bounded by
//! its section counts. A malformed message is shown up to the first error,
//! which is printed as a `;; ERROR:` line.

use core::fmt::{self, Write};

use crate::edns::{EdnsFlags, EdnsOption, Opt, OptHeader, OptionCode, RawOption};
use crate::message::{Message, Record, Section};
use crate::name::Name;
use crate::rdata::RData;
use crate::wire::WireReader;
use crate::{Class, Flags, Opcode, Result, Rtype};

/// A resource record as the formatter sees it: implemented by the borrowed
/// [`Record`] view and by the owned record type.
pub(crate) trait DigRecord {
    /// The owner name.
    fn name(&self) -> Name<'_>;
    /// TYPE.
    fn rtype(&self) -> Rtype;
    /// CLASS (raw).
    fn class(&self) -> Class;
    /// TTL (raw).
    fn ttl(&self) -> u32;
    /// The RDATA bytes (read for OPT, and shown in the generic form when
    /// the typed RDATA does not decode).
    fn raw_rdata(&self) -> &[u8];
    /// The typed RDATA.
    fn rdata(&self) -> Result<RData<'_>>;
}

/// A whole message as the formatter sees it.
pub(crate) trait DigMessage {
    /// The record type yielded by [`dig_records`](Self::dig_records).
    type Record<'r>: DigRecord
    where
        Self: 'r;

    /// The transaction ID.
    fn dig_id(&self) -> u16;
    /// The flags word.
    fn dig_flags(&self) -> Flags;
    /// The four section counts, in wire order.
    fn dig_counts(&self) -> [u16; 4];
    /// The question section.
    fn dig_questions(&self) -> impl Iterator<Item = Result<(Name<'_>, Rtype, Class)>>;
    /// The answer, authority and additional sections, in wire order.
    fn dig_records(&self) -> impl Iterator<Item = Result<(Section, Self::Record<'_>)>>;
    /// Octets after the last record (0 if the message does not parse).
    fn dig_trailing(&self) -> usize;
}

impl DigRecord for Record<'_> {
    #[inline]
    fn name(&self) -> Name<'_> {
        Record::name(self)
    }
    #[inline]
    fn rtype(&self) -> Rtype {
        Record::rtype(self)
    }
    #[inline]
    fn class(&self) -> Class {
        Record::class(self)
    }
    #[inline]
    fn ttl(&self) -> u32 {
        Record::ttl(self)
    }
    #[inline]
    fn raw_rdata(&self) -> &[u8] {
        Record::rdata(self)
    }
    #[inline]
    fn rdata(&self) -> Result<RData<'_>> {
        Record::data(self)
    }
}

impl<'a> DigMessage for Message<'a> {
    type Record<'r>
        = Record<'a>
    where
        Self: 'r;

    fn dig_id(&self) -> u16 {
        self.id()
    }

    fn dig_flags(&self) -> Flags {
        self.flags()
    }

    fn dig_counts(&self) -> [u16; 4] {
        let h = self.header();
        [h.qdcount, h.ancount, h.nscount, h.arcount]
    }

    fn dig_questions(&self) -> impl Iterator<Item = Result<(Name<'_>, Rtype, Class)>> {
        self.questions()
            .map(|q| q.map(|q| (q.name(), q.qtype(), q.qclass())))
    }

    fn dig_records(&self) -> impl Iterator<Item = Result<(Section, Record<'a>)>> {
        self.records()
    }

    fn dig_trailing(&self) -> usize {
        // The header is 12 octets; every entry ends where the next starts.
        let mut end = 12;
        for q in self.questions() {
            match q {
                Ok(q) => end = q.range().end,
                Err(_) => return 0,
            }
        }
        for rr in self.records() {
            match rr {
                Ok((_, rr)) => end = rr.end(),
                Err(_) => return 0,
            }
        }
        self.as_bytes().len().saturating_sub(end)
    }
}

impl fmt::Display for Message<'_> {
    /// The whole message in `dig` style: header, flags and counts, the OPT
    /// pseudosection, the four sections and the TSIG / SIG(0)
    /// pseudosections, in BIND 9's layout (header and flags lines, EDNS
    /// option lines, tab-aligned record columns). Needs no allocation; a
    /// malformed message is shown up to the first error, reported as
    /// `;; ERROR:`.
    ///
    /// ```
    /// use dnsbox::Message;
    ///
    /// let wire = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
    ///              \x07example\x03com\x00\x00\x01\x00\x01\
    ///              \xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x5d\xb8\xd8\x22";
    /// assert_eq!(
    ///     Message::parse(wire)?.to_string(),
    ///     ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4660\n\
    ///      ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n\
    ///      \n\
    ///      ;; QUESTION SECTION:\n\
    ///      ;example.com.\t\t\tIN\tA\n\
    ///      \n\
    ///      ;; ANSWER SECTION:\n\
    ///      example.com.\t\t3600\tIN\tA\t93.184.216.34\n\
    ///      \n",
    /// );
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_dig(f, self)
    }
}

/// BIND's default column layout (`dns_master_style_default`).
const TTL_COLUMN: usize = 24;
const CLASS_COLUMN: usize = 32;
const TYPE_COLUMN: usize = 40;
const RDATA_COLUMN: usize = 48;
const TAB_WIDTH: usize = 8;

/// A writer that tracks the current output column, for tab alignment.
struct Columns<'w, W: ?Sized> {
    w: &'w mut W,
    col: usize,
}

impl<W: Write + ?Sized> Write for Columns<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match s.rsplit_once('\n') {
            Some((_, tail)) => self.col = tail.chars().count(),
            None => self.col = self.col.saturating_add(s.chars().count()),
        }
        self.w.write_str(s)
    }
}

impl<W: Write + ?Sized> Columns<'_, W> {
    /// Moves to column `to` with tabs then spaces, always writing at least
    /// one character (BIND's `indent()` in `masterdump.c`).
    fn indent(&mut self, to: usize) -> fmt::Result {
        let from = self.col;
        let to = to.max(from.saturating_add(1));
        let tabs = to / TAB_WIDTH - from / TAB_WIDTH;
        let mut at = from;
        if tabs > 0 {
            for _ in 0..tabs {
                self.w.write_char('\t')?;
            }
            at = to / TAB_WIDTH * TAB_WIDTH;
        }
        for _ in at..to {
            self.w.write_char(' ')?;
        }
        self.col = to;
        Ok(())
    }
}

/// Pseudo-records shown outside the sections.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pseudo {
    Opt,
    Tsig,
    Sig0,
}

/// Classifies a record of the additional section.
fn pseudo<R: DigRecord>(section: Section, rr: &R) -> Option<Pseudo> {
    if section != Section::Additional {
        return None;
    }
    match rr.rtype() {
        Rtype::OPT => Some(Pseudo::Opt),
        Rtype::TSIG => Some(Pseudo::Tsig),
        // SIG(0): a SIG record covering type 0 (RFC 2931 §3).
        Rtype::SIG => match rr.rdata() {
            Ok(RData::Sig(s)) if s.type_covered.get() == 0 => Some(Pseudo::Sig0),
            _ => None,
        },
        _ => None,
    }
}

/// Section titles and count labels (RFC 2136 §2 renames them for UPDATE).
fn section_names(opcode: Opcode) -> [(&'static str, &'static str); 4] {
    if opcode == Opcode::UPDATE {
        [
            ("ZONE", "ZONE"),
            ("PREREQUISITE", "PREREQ"),
            ("UPDATE", "UPDATE"),
            ("ADDITIONAL", "ADDITIONAL"),
        ]
    } else {
        [
            ("QUESTION", "QUERY"),
            ("ANSWER", "ANSWER"),
            ("AUTHORITY", "AUTHORITY"),
            ("ADDITIONAL", "ADDITIONAL"),
        ]
    }
}

/// Writes a whole message in `dig` style.
pub(crate) fn fmt_dig<M: DigMessage + ?Sized, W: Write + ?Sized>(w: &mut W, m: &M) -> fmt::Result {
    let mut w = Columns { w, col: 0 };
    let flags = m.dig_flags();
    let opcode = flags.opcode();
    let names = section_names(opcode);
    let counts = m.dig_counts();

    // The first OPT record supplies the extended RCODE. Errors are reported
    // by the section walk below.
    let opt = m
        .dig_records()
        .map_while(|r| r.ok())
        .find(|(s, rr)| pseudo(*s, rr) == Some(Pseudo::Opt))
        .map(|(_, rr)| OptHeader::from_fields(rr.class(), rr.ttl()));
    let status = match opt {
        Some(h) => h.rcode(flags),
        None => flags.rcode(),
    };

    writeln!(
        w,
        ";; ->>HEADER<<- opcode: {opcode}, status: {status}, id: {}",
        m.dig_id()
    )?;
    w.write_str(";; flags:")?;
    for (set, name) in [
        (flags.qr(), " qr"),
        (flags.aa(), " aa"),
        (flags.tc(), " tc"),
        (flags.rd(), " rd"),
        (flags.ra(), " ra"),
        (flags.ad(), " ad"),
        (flags.cd(), " cd"),
        // The Z bit must be zero (RFC 1035 §4.1.1).
        (flags.z(), "; MBZ: 0x4"),
    ] {
        if set {
            w.write_str(name)?;
        }
    }
    w.write_str(";")?;
    for (i, ((_, label), count)) in names.iter().zip(counts).enumerate() {
        let sep = if i == 0 { " " } else { ", " };
        write!(w, "{sep}{label}: {count}")?;
    }
    w.write_str("\n")?;
    if flags.qr() && flags.rd() && !flags.ra() {
        w.write_str(";; WARNING: recursion requested but not available\n")?;
    }
    match m.dig_trailing() {
        0 => {}
        1 => w.write_str(";; WARNING: Message has 1 extra byte at end\n")?,
        n => writeln!(w, ";; WARNING: Message has {n} extra bytes at end")?,
    }
    w.write_str("\n")?;

    // OPT pseudosection.
    let mut opt_shown = false;
    for (s, rr) in m.dig_records().map_while(|r| r.ok()) {
        if pseudo(s, &rr) != Some(Pseudo::Opt) {
            continue;
        }
        if !opt_shown {
            w.write_str(";; OPT PSEUDOSECTION:\n")?;
            opt_shown = true;
        }
        fmt_opt(&mut w, &rr)?;
    }

    // Question section.
    if counts[0] > 0 {
        writeln!(w, ";; {} SECTION:", names[0].0)?;
        for q in m.dig_questions() {
            match q {
                Ok((name, qtype, qclass)) => {
                    // BIND does not count the `;` when aligning.
                    w.write_str(";")?;
                    w.col = 0;
                    write!(w, "{name}")?;
                    w.indent(CLASS_COLUMN)?;
                    write!(w, "{qclass}")?;
                    w.indent(TYPE_COLUMN)?;
                    writeln!(w, "{qtype}")?;
                }
                Err(e) => return writeln!(w, ";; ERROR: {e}"),
            }
        }
        w.write_str("\n")?;
    }

    // Answer, authority and additional sections.
    let mut current = None;
    let mut sig = false;
    for r in m.dig_records() {
        let (s, rr) = match r {
            Ok(x) => x,
            Err(e) => {
                if current.is_some() {
                    w.write_str("\n")?;
                }
                return writeln!(w, ";; ERROR: {e}");
            }
        };
        match pseudo(s, &rr) {
            Some(Pseudo::Opt) => continue,
            Some(_) => {
                sig = true;
                continue;
            }
            None => {}
        }
        if current != Some(s) {
            if current.is_some() {
                w.write_str("\n")?;
            }
            writeln!(w, ";; {} SECTION:", names[s.index()].0)?;
            current = Some(s);
        }
        fmt_record(&mut w, &rr)?;
    }
    if current.is_some() {
        w.write_str("\n")?;
    }

    // TSIG / SIG(0) pseudosections.
    if sig {
        for (s, rr) in m.dig_records().map_while(|r| r.ok()) {
            let title = match pseudo(s, &rr) {
                Some(Pseudo::Tsig) => "TSIG",
                Some(Pseudo::Sig0) => "SIG0",
                _ => continue,
            };
            writeln!(w, ";; {title} PSEUDOSECTION:")?;
            fmt_record(&mut w, &rr)?;
            w.write_str("\n")?;
        }
    }
    Ok(())
}

/// One record line: `name ttl class type rdata` in BIND's columns. RDATA
/// that fails to decode is shown in the generic RFC 3597 §5 form.
fn fmt_record<W: Write + ?Sized, R: DigRecord>(w: &mut Columns<'_, W>, rr: &R) -> fmt::Result {
    write!(w, "{}", rr.name())?;
    w.indent(TTL_COLUMN)?;
    write!(w, "{}", rr.ttl())?;
    w.indent(CLASS_COLUMN)?;
    write!(w, "{}", rr.class())?;
    w.indent(TYPE_COLUMN)?;
    write!(w, "{}", rr.rtype())?;
    w.indent(RDATA_COLUMN)?;
    match rr.rdata() {
        Ok(d) => write!(w, "{d}")?,
        Err(_) => crate::text::fmt_generic_rdata(w, rr.raw_rdata())?,
    }
    w.write_str("\n")
}

/// The `; EDNS:` line and one line per option of an OPT record.
fn fmt_opt<W: Write + ?Sized, R: DigRecord>(w: &mut W, rr: &R) -> fmt::Result {
    let header = OptHeader::from_fields(rr.class(), rr.ttl());
    write!(w, "; EDNS: version: {}, flags:", header.version)?;
    let bits = header.flags.bits();
    if bits & EdnsFlags::DO != 0 {
        w.write_str(" do")?;
    }
    if bits & EdnsFlags::CO != 0 {
        w.write_str(" co")?;
    }
    let mbz = bits & !(EdnsFlags::DO | EdnsFlags::CO);
    if mbz != 0 {
        write!(w, "; MBZ: {mbz:#06x}, udp: ")?;
    } else {
        w.write_str("; udp: ")?;
    }
    writeln!(w, "{}", header.udp_payload_size)?;
    match Opt::new(rr.raw_rdata()) {
        Ok(opt) => {
            for o in opt.raw_options() {
                fmt_option(w, o)?;
            }
            Ok(())
        }
        Err(e) => writeln!(w, ";; ERROR: {e}"),
    }
}

/// One EDNS option line, `; LABEL: value`, as BIND 9.18 prints it.
fn fmt_option<W: Write + ?Sized>(w: &mut W, o: RawOption<'_>) -> fmt::Result {
    let data = o.data;
    let parsed = o.parse();
    let valid = parsed.is_ok();
    match o.code {
        // RFC 5001 §2.3: `; NSID: 6e 72 74 30 39 ("nrt09")`.
        OptionCode::NSID => {
            w.write_str("; NSID:")?;
            fmt_hex_text(w, data)?;
        }
        // RFC 7871 §6: `; CLIENT-SUBNET: 198.51.100.0/24/0`.
        OptionCode::ECS if valid => {
            w.write_str("; CLIENT-SUBNET:")?;
            fmt_value(w, parsed)?;
        }
        // RFC 7314 §2: `; EXPIRE: 3600 (1 hour)`.
        OptionCode::EXPIRE if valid => {
            w.write_str("; EXPIRE:")?;
            if let Ok(&b) = <&[u8; 4]>::try_from(data) {
                let secs = u32::from_be_bytes(b);
                write!(w, " {secs} (")?;
                fmt_duration(w, secs)?;
                w.write_str(")")?;
            }
        }
        // RFC 7873 §4: the client and server cookies in hex.
        OptionCode::COOKIE if valid => {
            w.write_str("; COOKIE: ")?;
            for b in data {
                write!(w, "{b:02x}")?;
            }
        }
        // RFC 7828 §3.1: the timeout in units of 100 ms.
        OptionCode::TCP_KEEPALIVE if valid => {
            w.write_str("; TCP KEEPALIVE:")?;
            if let Ok(&b) = <&[u8; 2]>::try_from(data) {
                let t = u16::from_be_bytes(b);
                write!(w, " {}.{} secs", t / 10, t % 10)?;
            }
        }
        // RFC 7830 §3: only the length matters.
        OptionCode::PADDING => {
            w.write_str("; PAD:")?;
            if !data.is_empty() {
                write!(w, " ({} bytes)", data.len())?;
            }
        }
        // RFC 8145 §4.1: `; KEY-TAG: 20326, 38696`.
        OptionCode::KEY_TAG if valid => {
            w.write_str("; KEY-TAG:")?;
            for (i, pair) in data.as_chunks::<2>().0.iter().enumerate() {
                let sep = if i == 0 { " " } else { ", " };
                write!(w, "{sep}{}", u16::from_be_bytes(*pair))?;
            }
        }
        // RFC 8914 §2: `; EDE: 9 (DNSKEY Missing): (extra text)`.
        OptionCode::EDE if valid => {
            if let Ok(EdnsOption::ExtendedError(e)) = parsed {
                write!(w, "; EDE: {}", e.info_code.get())?;
                if let Some(p) = ede_purpose(e.info_code.get()) {
                    write!(w, " ({p})")?;
                }
                if !e.extra_text.is_empty() {
                    w.write_str(": (")?;
                    fmt_text(w, e.extra_text)?;
                    w.write_str(")")?;
                }
            }
        }
        // draft-bellis-dnsop-edns-tags: a 16-bit tag.
        OptionCode::CLIENT_TAG | OptionCode::SERVER_TAG if data.len() == 2 => {
            let label = if o.code == OptionCode::CLIENT_TAG {
                "CLIENT"
            } else {
                "SERVER"
            };
            let mut r = WireReader::new(data);
            if let Ok(tag) = r.read_u16() {
                write!(w, "; {label}-TAG: {tag}")?;
            }
        }
        // RFC 8764 §3.2: the LLQ fields.
        OptionCode::LLQ if data.len() == 18 => {
            if let Some((version, opcode, error, id, lease)) = llq(data) {
                write!(
                    w,
                    "; LLQ: Version: {version}, Opcode: {opcode}, Error: {error}, \
                     Identifier: {id}, Lifetime: {lease}"
                )?;
            }
        }
        code => match parsed {
            // An option `dig` does not know but dnsbox decodes: its
            // presentation value (`; CHAIN: example.`).
            Ok(opt) if !matches!(opt, EdnsOption::Unknown(_)) => {
                write!(w, "; {code}:")?;
                fmt_value(w, Ok(opt))?;
            }
            // `dig`'s form for options it does not decode.
            Ok(_) => {
                write!(w, "; OPT={}:", code.get())?;
                fmt_hex_text(w, data)?;
            }
            // A malformed option: its data in hex.
            Err(_) => {
                write!(w, "; {}:", option_label(code))?;
                fmt_hex_text(w, data)?;
            }
        },
    }
    w.write_str("\n")
}

/// The LLQ fields (RFC 8764 §3.2): version, opcode, error, ID, lease.
fn llq(data: &[u8]) -> Option<(u16, u16, u16, u64, u32)> {
    let mut r = WireReader::new(data);
    Some((
        r.read_u16().ok()?,
        r.read_u16().ok()?,
        r.read_u16().ok()?,
        r.read_u64().ok()?,
        r.read_u32().ok()?,
    ))
}

/// The name `dig` gives an option code.
fn option_label(code: OptionCode) -> &'static str {
    match code {
        OptionCode::ECS => "CLIENT-SUBNET",
        OptionCode::TCP_KEEPALIVE => "TCP KEEPALIVE",
        OptionCode::PADDING => "PAD",
        c => c.mnemonic().unwrap_or("OPT"),
    }
}

/// The purpose text of an EDE INFO-CODE, spelled as `dig` spells it.
fn ede_purpose(code: u16) -> Option<&'static str> {
    match code {
        0 => Some("Other"),
        19 => Some("Stale NXDOMAIN Answer"),
        c => crate::edns::InfoCode::new(c).mnemonic(),
    }
}

/// Writes the presentation value of a decoded option: what follows the
/// `=` of its `Display` (`ECS=192.0.2.0/24/0` → ` 192.0.2.0/24/0`), or
/// nothing for a value-less option.
fn fmt_value<W: Write + ?Sized>(w: &mut W, parsed: Result<EdnsOption<'_>>) -> fmt::Result {
    match parsed {
        Ok(opt) => write!(
            AfterEq {
                w,
                seen: false,
                started: false,
            },
            "{opt}"
        ),
        Err(_) => Ok(()),
    }
}

/// Writes ` 6e 72 74 30 39 ("nrt09")`: every octet in hex, then the
/// printable ASCII characters (others as `.`); nothing for empty data.
fn fmt_hex_text<W: Write + ?Sized>(w: &mut W, data: &[u8]) -> fmt::Result {
    if data.is_empty() {
        return Ok(());
    }
    for b in data {
        write!(w, " {b:02x}")?;
    }
    w.write_str(" (\"")?;
    for &b in data {
        w.write_char(if (0x20..0x7f).contains(&b) {
            char::from(b)
        } else {
            '.'
        })?;
    }
    w.write_str("\")")
}

/// Writes UTF-8 text with control characters and invalid octets as `.`.
fn fmt_text<W: Write + ?Sized>(w: &mut W, text: &[u8]) -> fmt::Result {
    for chunk in text.utf8_chunks() {
        for c in chunk.valid().chars() {
            w.write_char(if c.is_control() { '.' } else { c })?;
        }
        for _ in chunk.invalid() {
            w.write_char('.')?;
        }
    }
    Ok(())
}

/// Writes a duration as BIND's verbose TTL text: `1 hour 1 minute 1
/// second`, `0 seconds`.
fn fmt_duration<W: Write + ?Sized>(w: &mut W, secs: u32) -> fmt::Result {
    let mut rest = secs;
    let mut first = true;
    for (size, unit) in [
        (604_800, "week"),
        (86_400, "day"),
        (3_600, "hour"),
        (60, "minute"),
        (1, "second"),
    ] {
        let n = rest / size;
        rest %= size;
        if n == 0 {
            continue;
        }
        let sep = if first { "" } else { " " };
        let plural = if n == 1 { "" } else { "s" };
        write!(w, "{sep}{n} {unit}{plural}")?;
        first = false;
    }
    if first {
        w.write_str("0 seconds")?;
    }
    Ok(())
}

/// Passes through what follows the first `=` of an option's `Display`,
/// prefixed with a space, writing nothing for a value-less option.
struct AfterEq<'w, W: ?Sized> {
    w: &'w mut W,
    seen: bool,
    started: bool,
}

impl<W: Write + ?Sized> Write for AfterEq<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let rest = if self.seen {
            s
        } else {
            match s.split_once('=') {
                Some((_, rest)) => {
                    self.seen = true;
                    rest
                }
                None => return Ok(()),
            }
        };
        if rest.is_empty() {
            return Ok(());
        }
        if !self.started {
            self.started = true;
            self.w.write_str(" ")?;
        }
        self.w.write_str(rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::hex;
    use std::string::{String, ToString};

    #[test]
    fn indent_matches_bind() {
        let mut s = String::new();
        let mut w = Columns { w: &mut s, col: 0 };
        w.write_str("example.com.").unwrap();
        w.indent(TTL_COLUMN).unwrap();
        w.write_str("3600").unwrap();
        w.indent(CLASS_COLUMN).unwrap();
        assert_eq!(s, "example.com.\t\t3600\t");
        // Past the column: a single space.
        let mut s = String::new();
        let mut w = Columns { w: &mut s, col: 0 };
        w.write_str("a-rather-long-owner-name.example.com.")
            .unwrap();
        w.indent(TTL_COLUMN).unwrap();
        w.write_str("300").unwrap();
        w.indent(CLASS_COLUMN).unwrap();
        assert_eq!(s, "a-rather-long-owner-name.example.com. 300 ");
        // Spaces after the tabs when the target is not a tab stop.
        let mut s = String::new();
        let mut w = Columns { w: &mut s, col: 0 };
        w.write_str("ab").unwrap();
        w.indent(10).unwrap();
        // A newline resets the column.
        w.write_str("x\nab").unwrap();
        w.indent(8).unwrap();
        assert_eq!(s, "ab\t  x\nab\t");
    }

    #[test]
    fn after_eq() {
        let mut s = String::new();
        let mut a = AfterEq {
            w: &mut s,
            seen: false,
            started: false,
        };
        a.write_str("ECS=192.0.2.0/24/0").unwrap();
        assert_eq!(s, " 192.0.2.0/24/0");
        let mut s = String::new();
        let mut a = AfterEq {
            w: &mut s,
            seen: false,
            started: false,
        };
        a.write_str("TCP-KEEPALIVE").unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn text_escapes() {
        let mut s = String::new();
        fmt_text(&mut s, b"a\\b\x00\xffc\xc3\xa9\x7f\n").unwrap();
        assert_eq!(s, "a\\b..c\u{e9}..");
    }

    #[test]
    fn durations() {
        // Checked against `dig` 9.18's EXPIRE lines.
        for (secs, text) in [
            (0, "0 seconds"),
            (1, "1 second"),
            (60, "1 minute"),
            (61, "1 minute 1 second"),
            (3661, "1 hour 1 minute 1 second"),
            (90061, "1 day 1 hour 1 minute 1 second"),
            (604800, "1 week"),
            (694861, "1 week 1 day 1 hour 1 minute 1 second"),
            (u32::MAX, "7101 weeks 3 days 6 hours 28 minutes 15 seconds"),
        ] {
            let mut s = String::new();
            fmt_duration(&mut s, secs).unwrap();
            assert_eq!(s, text);
        }
    }

    #[test]
    fn truncated_messages_never_panic() {
        // A response with EDNS, then every truncation and a few mutations.
        let wire = hex("abcd 8180 0001 0001 0000 0001
             07 6578616d706c65 03 636f6d 00 0001 0001
             c00c 0001 0001 00000e10 0004 5db8d822
             00 0029 04d0 00008000 0006 000f 0002 0012");
        let full = Message::parse(&wire).unwrap().to_string();
        assert!(full.contains("; EDE: 18 (Prohibited)\n"), "{full}");
        for len in 0..wire.len() {
            if let Ok(m) = Message::parse(&wire[..len]) {
                let s = m.to_string();
                assert!(s.contains(";; ERROR: "), "{len}: {s}");
            }
        }
        for i in 0..wire.len() {
            for v in [0x00, 0x01, 0x3f, 0x80, 0xc0, 0xff] {
                let mut w = wire.clone();
                w[i] = v;
                if let Ok(m) = Message::parse(&w) {
                    let _ = m.to_string();
                }
            }
        }
    }

    #[test]
    fn error_line_ends_output() {
        // QDCOUNT 1 but no question.
        let m = Message::parse(b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00").unwrap();
        assert_eq!(
            m.to_string(),
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n\
             ;; flags:; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n\n\
             ;; QUESTION SECTION:\n\
             ;; ERROR: unexpected end of input\n"
        );
    }

    #[test]
    fn unparsable_rdata_shows_generic_form() {
        // An A record with three bytes of RDATA.
        let wire = hex("0001 8400 0000 0001 0000 0000
             00 0001 0001 00000000 0003 010203");
        let s = Message::parse(&wire).unwrap().to_string();
        assert!(s.contains(".\t\t\t0\tIN\tA\t\\# 3 010203\n"), "{s}");
        assert!(s.contains(";; flags: qr aa;"), "{s}");
        assert!(!s.contains("QUESTION SECTION"), "{s}");
    }

    #[test]
    fn header_warnings_and_mbz() {
        // `dig` 9.18 on a response with RD, no RA, the Z bit and two
        // trailing octets.
        let wire = hex("0007 8140 0000 0000 0000 0000 ffff");
        assert_eq!(
            Message::parse(&wire).unwrap().to_string(),
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7\n\
             ;; flags: qr rd; MBZ: 0x4; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n\
             ;; WARNING: recursion requested but not available\n\
             ;; WARNING: Message has 2 extra bytes at end\n\n"
        );
        // Queries get no recursion warning; one extra octet is singular.
        let wire = hex("0007 0100 0000 0000 0000 0000 00");
        assert_eq!(
            Message::parse(&wire).unwrap().to_string(),
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7\n\
             ;; flags: rd; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n\
             ;; WARNING: Message has 1 extra byte at end\n\n"
        );
    }

    #[test]
    fn edns_header_line() {
        // BADVERS (extended RCODE 1), version 1, DO plus an unknown flag:
        // `dig` 9.18 output.
        let wire = hex("0001 8180 0000 0000 0000 0001
             00 0029 04d0 01018001 0000");
        let s = Message::parse(&wire).unwrap().to_string();
        assert!(
            s.starts_with(";; ->>HEADER<<- opcode: QUERY, status: BADVERS, id: 1\n"),
            "{s}"
        );
        assert!(
            s.ends_with(
                ";; OPT PSEUDOSECTION:\n\
                 ; EDNS: version: 1, flags: do; MBZ: 0x0001, udp: 1232\n"
            ),
            "{s}"
        );
    }

    /// Formats the options of an OPT RDATA, one line each.
    fn options(opts: &str) -> String {
        let opts = hex(opts);
        let mut s = String::new();
        for o in Opt::new(&opts).unwrap().raw_options() {
            fmt_option(&mut s, o).unwrap();
        }
        s
    }

    #[test]
    fn options_as_dig_shows_them() {
        // Every line was checked against `dig` 9.18.49 receiving the same
        // option.
        assert_eq!(
            options(
                "0003 0003 6e7331  0003 0000
                 0003 0003 00ff41
                 0008 0007 0001 1800 c63364
                 0008 000b 0002 3830 20010db80000ff
                 0008 0004 0001 0000
                 000a 0018 0001020304050607 101112131415161718191a1b1c1d1e1f
                 000a 0008 0001020304050607
                 000b 0002 012c  000b 0000  000b 0002 0007  000b 0002 ffff
                 000c 0007 00000000000000  000c 0000
                 0009 0004 00000e10  0009 0000
                 000e 0004 4f660014
                 000f 0008 0009 6e6f20534550
                 000f 0002 0012
                 000f 0003 0100 78
                 000f 0005 0016 610a62
                 000f 0007 0000 636166c3a9
                 000f 0008 0000 5c782279 7f7e
                 0010 0002 0007  0011 0002 0008
                 0001 0012 000000000000000000000000000000000000
                 0002 0004 00000e10
                 fde9 0004 c0ff6162  fdea 0000"
            ),
            "; NSID: 6e 73 31 (\"ns1\")\n\
             ; NSID:\n\
             ; NSID: 00 ff 41 (\"..A\")\n\
             ; CLIENT-SUBNET: 198.51.100.0/24/0\n\
             ; CLIENT-SUBNET: 2001:db8:0:ff00::/56/48\n\
             ; CLIENT-SUBNET: 0.0.0.0/0/0\n\
             ; COOKIE: 0001020304050607101112131415161718191a1b1c1d1e1f\n\
             ; COOKIE: 0001020304050607\n\
             ; TCP KEEPALIVE: 30.0 secs\n\
             ; TCP KEEPALIVE:\n\
             ; TCP KEEPALIVE: 0.7 secs\n\
             ; TCP KEEPALIVE: 6553.5 secs\n\
             ; PAD: (7 bytes)\n\
             ; PAD:\n\
             ; EXPIRE: 3600 (1 hour)\n\
             ; EXPIRE:\n\
             ; KEY-TAG: 20326, 20\n\
             ; EDE: 9 (DNSKEY Missing): (no SEP)\n\
             ; EDE: 18 (Prohibited)\n\
             ; EDE: 256: (x)\n\
             ; EDE: 22 (No Reachable Authority): (a.b)\n\
             ; EDE: 0 (Other): (caf\u{e9})\n\
             ; EDE: 0 (Other): (\\x\"y.~)\n\
             ; CLIENT-TAG: 7\n\
             ; SERVER-TAG: 8\n\
             ; LLQ: Version: 0, Opcode: 0, Error: 0, Identifier: 0, Lifetime: 0\n\
             ; OPT=2: 00 00 0e 10 (\"....\")\n\
             ; OPT=65001: c0 ff 61 62 (\"..ab\")\n\
             ; OPT=65002:\n"
        );
    }

    #[test]
    fn options_dig_does_not_decode() {
        // dnsbox's presentation value for options `dig` 9.18 shows as
        // `OPT=<code>`, and the raw data of malformed options.
        assert_eq!(
            options(
                "000d 000d 076578616d706c6503636f6d00
                 0005 0002 080d  0006 0000
                 0012 000f 056167656e74076578616d706c6500
                 0013 0006 020000000001  0013 0000
                 000e 0003 010203
                 0008 0003 000120
                 000b 0003 010203
                 000a 0003 010203
                 0009 0002 0102
                 000f 0001 00
                 0010 0001 07"
            ),
            "; CHAIN: example.com.\n\
             ; DAU: 8,13\n\
             ; DHU:\n\
             ; REPORT-CHANNEL: agent.example.\n\
             ; ZONEVERSION: 2,SOA-SERIAL,1\n\
             ; ZONEVERSION:\n\
             ; KEY-TAG: 01 02 03 (\"...\")\n\
             ; CLIENT-SUBNET: 00 01 20 (\".. \")\n\
             ; TCP KEEPALIVE: 01 02 03 (\"...\")\n\
             ; COOKIE: 01 02 03 (\"...\")\n\
             ; EXPIRE: 01 02 (\"..\")\n\
             ; EDE: 00 (\".\")\n\
             ; OPT=16: 07 (\".\")\n"
        );
    }
}
