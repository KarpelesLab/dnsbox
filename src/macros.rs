//! Crate-internal macros shared by many modules.

/// Defines an open newtype over an integer for a protocol registry (RFC 3597
/// spirit: unknown values round-trip), with:
///
/// - one associated constant per registered value;
/// - `new`, `get`, `mnemonic`, `from_mnemonic` (ASCII case-insensitive,
///   aliases included) and `all`;
/// - `From` conversions to and from the integer;
/// - `Display` / `Debug` printing the mnemonic, or `<generic><number>` for
///   unregistered values (e.g. `TYPE65534`, `CLASS42`, `key65535`; use an
///   empty generic prefix to print bare numbers);
/// - `FromStr` accepting a mnemonic, an alias, or the generic form;
/// - with the `serde` feature, `Serialize` / `Deserialize` (the mnemonic or
///   generic form in human-readable formats, the number otherwise).
///
/// `in <path>` names the public module the type is reachable from: the
/// generated methods' doctests import it from there, and use the first
/// registered value as their example.
///
/// ```ignore
/// open_enum! {
///     /// An EDNS(0) option code (RFC 6891 §6.1.2).
///     pub struct OptionCode(u16) in dnsbox::edns, generic "OPT", aliases { "CLIENT-SUBNET" => ECS };
///     /// Client subnet (RFC 7871).
///     ECS = 8 => "ECS",
///     /// Cookie (RFC 7873).
///     COOKIE = 10 => "COOKIE",
/// }
/// ```
macro_rules! open_enum {
    (
        $(#[$meta:meta])*
        pub struct $name:ident($int:ty) in $($path:ident)::+, generic $prefix:literal
            $(, aliases { $( $alias:literal => $target:ident ),* $(,)? } )?;
        $( $(#[$doc:meta])* $konst:ident = $val:literal => $mn:literal, )*
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name($int);

        impl $name {
            $(
                $(#[$doc])*
                pub const $konst: $name = $name($val);
            )*

            /// Every registered (value, mnemonic) pair, in declaration order.
            const REGISTRY: &'static [($name, &'static str)] = &[ $( ($name($val), $mn), )* ];

            /// Builds a value from its number.
            #[doc = open_enum_example!(new; [$($path)::+] $name($int); $( $konst = $val => $mn, )*)]
            #[inline]
            #[must_use]
            pub const fn new(value: $int) -> Self {
                $name(value)
            }

            /// The numeric value.
            #[doc = open_enum_example!(get; [$($path)::+] $name($int); $( $konst = $val => $mn, )*)]
            #[inline]
            #[must_use]
            pub const fn get(self) -> $int {
                self.0
            }

            /// The registered mnemonic for this value, if any.
            #[doc = open_enum_example!(mnemonic; [$($path)::+] $name($int); $( $konst = $val => $mn, )*)]
            #[must_use]
            pub const fn mnemonic(self) -> Option<&'static str> {
                match self.0 {
                    $( $val => Some($mn), )*
                    _ => None,
                }
            }

            /// Looks up a mnemonic or alias, ASCII-case-insensitively. Does
            /// not accept the generic numeric form; [`FromStr`] does.
            ///
            #[doc = open_enum_example!(from_mnemonic; [$($path)::+] $name($int); $( $konst = $val => $mn, )*)]
            ///
            /// [`FromStr`]: core::str::FromStr
            #[must_use]
            pub fn from_mnemonic(s: &str) -> Option<Self> {
                const ALIASES: &[(&str, $name)] = &[ $( $( ($alias, $name::$target), )* )? ];
                Self::REGISTRY
                    .iter()
                    .map(|&(v, m)| (m, v))
                    .chain(ALIASES.iter().copied())
                    .find(|(m, _)| m.eq_ignore_ascii_case(s))
                    .map(|(_, v)| v)
            }

            /// Iterates over every registered value and its mnemonic.
            #[doc = open_enum_example!(all; [$($path)::+] $name($int); $( $konst = $val => $mn, )*)]
            pub fn all() -> impl Iterator<Item = (Self, &'static str)> {
                Self::REGISTRY.iter().copied()
            }
        }

        impl From<$int> for $name {
            #[inline]
            fn from(v: $int) -> Self {
                $name(v)
            }
        }

        impl From<$name> for $int {
            #[inline]
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl core::str::FromStr for $name {
            type Err = $crate::Error;

            /// Parses a mnemonic, an alias, or the generic numeric form
            #[doc = concat!("(`", $prefix, "<number>`), ASCII-case-insensitively.")]
            fn from_str(s: &str) -> $crate::Result<Self> {
                if let Some(v) = Self::from_mnemonic(s) {
                    return Ok(v);
                }
                match $crate::macros::generic_digits(s, $prefix) {
                    Some(Some(digits)) => digits
                        .parse::<$int>()
                        .map($name)
                        .map_err(|_| $crate::Error::InvalidText),
                    Some(None) => Err($crate::Error::InvalidText),
                    None => Err($crate::Error::UnknownMnemonic),
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self.mnemonic() {
                    Some(m) => f.write_str(m),
                    None => write!(f, concat!($prefix, "{}"), self.0),
                }
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(self, f)
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            /// The mnemonic or generic form in human-readable formats, the
            /// number otherwise.
            fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
                $crate::serde_impls::serialize_open(s, self, self.0)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            /// A mnemonic, an alias, the generic form or a number in
            /// human-readable formats; the number otherwise.
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
                $crate::serde_impls::deserialize_open::<D, $name, $int>(
                    d,
                    concat!("a ", stringify!($name), " mnemonic or number"),
                    $crate::serde_impls::parse_from_str,
                    |v| <$int>::try_from(v).ok().map($name),
                )
            }
        }
    };
}

/// The doctest of a method generated by [`open_enum!`], exercising the
/// type's first registered value.
macro_rules! open_enum_example {
    (
        $method:ident; [$($path:ident)::+] $name:ident($int:ty);
        $konst:ident = $val:literal => $mn:literal, $($rest:tt)*
    ) => {
        concat!(
            "\n```\nuse ", $(stringify!($path), "::",)+ stringify!($name), ";\n\n",
            open_enum_example!(@$method $name, $int, $konst, $val, $mn),
            "```",
        )
    };
    (@new $name:ident, $int:ty, $konst:ident, $val:literal, $mn:literal) => {
        concat!(
            "let value = ", stringify!($name), "::new(", stringify!($val), ");\n",
            "assert_eq!(value, ", stringify!($name), "::", stringify!($konst), ");\n",
            "assert_eq!(value.to_string(), \"", $mn, "\");\n",
        )
    };
    (@get $name:ident, $int:ty, $konst:ident, $val:literal, $mn:literal) => {
        concat!(
            "assert_eq!(", stringify!($name), "::", stringify!($konst), ".get(), ", stringify!($val), ");\n",
            "assert_eq!(", stringify!($int), "::from(", stringify!($name), "::", stringify!($konst), "), ",
            stringify!($val), ");\n",
        )
    };
    (@mnemonic $name:ident, $int:ty, $konst:ident, $val:literal, $mn:literal) => {
        concat!(
            "assert_eq!(", stringify!($name), "::", stringify!($konst), ".mnemonic(), Some(\"", $mn, "\"));\n",
            "// Unregistered values have none, and display in the generic form.\n",
            "let unknown = (0..=", stringify!($int), "::MAX).map(", stringify!($name),
            "::new).find(|v| v.mnemonic().is_none());\n",
            "assert!(unknown.is_some_and(|v| v.to_string().parse() == Ok(v)));\n",
        )
    };
    (@from_mnemonic $name:ident, $int:ty, $konst:ident, $val:literal, $mn:literal) => {
        concat!(
            "assert_eq!(", stringify!($name), "::from_mnemonic(\"", $mn, "\"), Some(",
            stringify!($name), "::", stringify!($konst), "));\n",
            "let lower = \"", $mn, "\".to_ascii_lowercase();\n",
            "assert_eq!(", stringify!($name), "::from_mnemonic(&lower), Some(",
            stringify!($name), "::", stringify!($konst), "));\n",
            "assert_eq!(", stringify!($name), "::from_mnemonic(\"no such mnemonic\"), None);\n",
        )
    };
    (@all $name:ident, $int:ty, $konst:ident, $val:literal, $mn:literal) => {
        concat!(
            "let all: Vec<(", stringify!($name), ", &str)> = ", stringify!($name), "::all().collect();\n",
            "assert_eq!(all[0], (", stringify!($name), "::", stringify!($konst), ", \"", $mn, "\"));\n",
            "// Every pair round-trips through the mnemonic lookup.\n",
            "assert!(all.iter().all(|&(v, m)| ", stringify!($name), "::from_mnemonic(m) == Some(v)));\n",
        )
    };
}

/// Splits the generic `<prefix><digits>` form (RFC 3597 §5 style).
///
/// Returns `None` if `s` does not start with `prefix` (case-insensitively),
/// `Some(None)` if it does but is not followed by one or more ASCII digits,
/// and `Some(Some(digits))` otherwise.
pub(crate) fn generic_digits<'s>(s: &'s str, prefix: &str) -> Option<Option<&'s str>> {
    let head = s.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let digits = s.get(prefix.len()..)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Some(None);
    }
    Some(Some(digits))
}

#[cfg(test)]
mod tests {
    open_enum! {
        /// Test registry with a bare-number generic form.
        pub struct Small(u8) in crate::macros::tests, generic "", aliases { "UNO" => ONE };
        /// One.
        ONE = 1 => "ONE",
    }

    #[test]
    fn bare_numbers() {
        use std::string::ToString;
        assert_eq!("uno".parse(), Ok(Small::ONE));
        assert_eq!("7".parse(), Ok(Small::new(7)));
        assert_eq!("256".parse::<Small>(), Err(crate::Error::InvalidText));
        assert_eq!("x".parse::<Small>(), Err(crate::Error::InvalidText));
        assert_eq!(Small::new(7).to_string(), "7");
        assert_eq!(Small::all().count(), 1);
        assert_eq!(u8::from(Small::from(3)), 3);
        assert_eq!(Small::default().get(), 0);
    }
}
