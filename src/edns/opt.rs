//! The OPT record's RDATA: a list of options (RFC 6891 §6.1.2).

use core::fmt;

use super::{ComposeOption, EdnsOption, OptionCode, ParseOption, fmt_hex_option};
use crate::rdata::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Error, Result, Rtype};

/// `OPT` record data: a sequence of `{OPTION-CODE, OPTION-LENGTH,
/// OPTION-DATA}` triples (RFC 6891 §6.1.2).
///
/// Constructing an `Opt` checks the framing (every option is complete), so
/// [raw iteration](Self::raw_options) cannot fail; the option values are
/// only decoded on demand by [`options`](Self::options) or
/// [`get`](Self::get), and a malformed value only affects that option.
/// Use [`validate`](Self::validate) to check every typed option at once.
///
/// The header fields of the OPT record (UDP payload size, extended RCODE,
/// version, flags) live in its CLASS and TTL; see
/// [`Edns`](super::Edns) / [`OptHeader`](super::OptHeader).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Opt<'a> {
    data: &'a [u8],
}

impl<'a> Opt<'a> {
    /// An OPT RDATA with no options.
    pub const EMPTY: Opt<'static> = Opt { data: &[] };

    /// Wraps encoded options, checking that every option is complete.
    /// A truncated option yields [`Error::UnexpectedEof`].
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let mut r = WireReader::new(data);
        while !r.is_empty() {
            r.skip(2)?;
            let len = r.read_u16()?;
            r.skip(len as usize)?;
        }
        Ok(Opt { data })
    }

    /// The encoded options.
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Whether there are no options.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Iterates over the options without decoding their values.
    #[inline]
    pub fn raw_options(&self) -> RawOptions<'a> {
        RawOptions {
            r: WireReader::new(self.data),
        }
    }

    /// Iterates over the options, decoding each into an [`EdnsOption`].
    ///
    /// A malformed option value yields an error for that option only;
    /// iteration continues with the next one (the framing is known good).
    #[inline]
    pub fn options(&self) -> Options<'a> {
        Options {
            raw: self.raw_options(),
        }
    }

    /// The first option with code `code`, undecoded.
    pub fn find(&self, code: OptionCode) -> Option<RawOption<'a>> {
        self.raw_options().find(|o| o.code == code)
    }

    /// Decodes the first option of type `T`, if there is one.
    pub fn get<T: ParseOption<'a>>(&self) -> Option<Result<T>> {
        self.find(T::CODE).map(|o| o.parse_as())
    }

    /// Checks that every option with a typed implementation decodes.
    pub fn validate(&self) -> Result<()> {
        self.options().try_for_each(|o| o.map(|_| ()))
    }
}

impl<'a> ParseRdata<'a> for Opt<'a> {
    const RTYPE: Rtype = Rtype::OPT;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Opt::new(rdata.peek_rest()).inspect(|_| {
            rdata.read_rest();
        })
    }
}

impl ComposeRdata for Opt<'_> {
    #[inline]
    fn rtype(&self) -> Rtype {
        Rtype::OPT
    }

    #[inline]
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.data)
    }
}

impl fmt::Display for Opt<'_> {
    /// The options, space-separated, each as `MNEMONIC` or
    /// `MNEMONIC=value` (see [`EdnsOption`]'s `Display`). OPT has no
    /// zone-file syntax; an empty option list is shown in the generic
    /// RFC 3597 §5 form, `\# 0`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return crate::text::fmt_generic_rdata(f, &[]);
        }
        for (i, o) in self.raw_options().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            fmt::Display::fmt(&o, f)?;
        }
        Ok(())
    }
}

/// One option of an [`Opt`], undecoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RawOption<'a> {
    /// OPTION-CODE.
    pub code: OptionCode,
    /// OPTION-DATA (OPTION-LENGTH bytes).
    pub data: &'a [u8],
}

impl<'a> RawOption<'a> {
    /// Decodes the option into an [`EdnsOption`].
    #[inline]
    pub fn parse(&self) -> Result<EdnsOption<'a>> {
        EdnsOption::parse(self.code, WireReader::new(self.data))
    }

    /// Decodes the option as `T`, failing with [`Error::WrongType`] if it
    /// has another code.
    pub fn parse_as<T: ParseOption<'a>>(&self) -> Result<T> {
        if self.code != T::CODE {
            return Err(Error::WrongType);
        }
        let mut r = WireReader::new(self.data);
        let opt = T::parse_option(&mut r)?;
        r.finish()?;
        Ok(opt)
    }
}

impl ComposeOption for RawOption<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        self.code
    }

    #[inline]
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.data)
    }
}

impl fmt::Display for RawOption<'_> {
    /// The typed presentation if the value decodes, `CODE=HEX` otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.parse() {
            Ok(o) => fmt::Display::fmt(&o, f),
            Err(_) => fmt_hex_option(f, self.code, self.data),
        }
    }
}

/// Iterator over the options of an [`Opt`]; see [`Opt::raw_options`].
#[derive(Clone, Debug)]
pub struct RawOptions<'a> {
    r: WireReader<'a>,
}

impl<'a> Iterator for RawOptions<'a> {
    type Item = RawOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.r.is_empty() {
            return None;
        }
        let mut r = self.r;
        // Errors are unreachable for an `Opt` (framing is checked on
        // construction); stop rather than loop.
        self.r.read_rest();
        let code = OptionCode::new(r.read_u16().ok()?);
        let len = r.read_u16().ok()?;
        let data = r.read_bytes(len as usize).ok()?;
        self.r = r;
        Some(RawOption { code, data })
    }
}

impl core::iter::FusedIterator for RawOptions<'_> {}

/// Iterator over the decoded options of an [`Opt`]; see [`Opt::options`].
#[derive(Clone, Debug)]
pub struct Options<'a> {
    raw: RawOptions<'a>,
}

impl<'a> Iterator for Options<'a> {
    type Item = Result<EdnsOption<'a>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.raw.next().map(|o| o.parse())
    }
}

impl core::iter::FusedIterator for Options<'_> {}
