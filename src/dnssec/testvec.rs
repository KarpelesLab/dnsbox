//! Shared DNSSEC test vectors (hex), from the RFCs named on each item.

/// RFC 4034 §2.3: example.com. DNSKEY 256 3 5 AQPSKmyn... (key tag 2642).
pub(crate) const RFC4034_KEY: &str = "
    010003050103d22a6ca77f35b893206fd35e4c506d8378843709b97e041647e1
    bff43d8d64c649af1e371973c9e891fce3df519a8c840a63ee42a6d2ebddbb97
    035d215aa4e417b1fa45fa11a9741ea2098c1dfa5fb5feb332fd4bc8152089ae
    f36ba644cce2413b3b72be18cbef8da253f4e93d2103866d9234a2e28df529a6
    7d5468dbefe3";

/// RFC 4034 §5.4: dskey.example.com. DNSKEY 256 3 5 AQOeiiR0... (key tag
/// 60485).
pub(crate) const RFC4034_DSKEY: &str = "
    0100030501039e8a247418e318903b215a848acfd5f37f026bd4062db26c774c
    690968d5d56df8bfda91e6f36d9a279888f41333357c5e6029990d10fdf56630
    62a512763326980a615ddbf17a05ddfcce7e5fb3abcca05a31b0957452d4521e
    83870789063115bf97f6c308ccf57cdc9ce7fe10f6ed1bd0cc0660038c50dcdb
    0feb963c2f17";
