//! ZONEMD tests: the RFC 8976 Appendix A example zones (simple, complex,
//! multiple digests, URI.ARPA signed with DNSSEC, ROOT-SERVERS.NET), the
//! inclusion/exclusion rules, ordering and duplicates, and every
//! verification failure.

use super::*;
use crate::Error;
use crate::dnssec::testvec::b64;
use crate::rdata::{
    A, Aaaa, Dnskey, Mx, Ns, Nsec, Ptr, RData, Rrsig, Soa, TypeBitmap, UnknownRdata,
};
use crate::testutil::hex;
use crate::wire::WireWriter;
use std::string::{String, ToString};
use std::vec;

fn name(s: &str) -> NameBuf {
    NameBuf::from_text(s.as_bytes()).unwrap()
}

/// A zone under construction: owned records, turned into
/// [`ZonemdRecord`]s of [`RData`] for collation.
#[derive(Default)]
struct Zone {
    rrs: Vec<(NameBuf, u32, Rtype, Vec<u8>)>,
}

impl Zone {
    fn add<D: ComposeRdata>(&mut self, owner: &str, ttl: u32, data: D) -> &mut Self {
        let mut buf = [0u8; 4096];
        let mut w = WireWriter::new(&mut buf);
        data.compose_rdata(&mut w).unwrap();
        self.raw(owner, ttl, data.rtype(), w.as_bytes())
    }

    fn raw(&mut self, owner: &str, ttl: u32, rtype: Rtype, rdata: &[u8]) -> &mut Self {
        self.rrs.push((name(owner), ttl, rtype, rdata.to_vec()));
        self
    }

    fn soa(&mut self, owner: &str, ttl: u32, mname: &str, rname: &str, f: [u32; 5]) -> &mut Self {
        let (m, r) = (name(mname), name(rname));
        self.add(
            owner,
            ttl,
            Soa {
                mname: m.as_name(),
                rname: r.as_name(),
                serial: f[0],
                refresh: f[1],
                retry: f[2],
                expire: f[3],
                minimum: f[4],
            },
        )
    }

    fn ns(&mut self, owner: &str, ttl: u32, target: &str) -> &mut Self {
        let t = name(target);
        self.add(owner, ttl, Ns::new(t.as_name()))
    }

    fn ptr(&mut self, owner: &str, ttl: u32, target: &str) -> &mut Self {
        let t = name(target);
        self.add(owner, ttl, Ptr::new(t.as_name()))
    }

    fn mx(&mut self, owner: &str, ttl: u32, preference: u16, exchange: &str) -> &mut Self {
        let e = name(exchange);
        self.add(
            owner,
            ttl,
            Mx {
                preference,
                exchange: e.as_name(),
            },
        )
    }

    fn a(&mut self, owner: &str, ttl: u32, addr: &str) -> &mut Self {
        self.add(owner, ttl, A::new(addr.parse().unwrap()))
    }

    fn aaaa(&mut self, owner: &str, ttl: u32, addr: &str) -> &mut Self {
        self.add(owner, ttl, Aaaa::new(addr.parse().unwrap()))
    }

    fn txt(&mut self, owner: &str, ttl: u32, text: &str) -> &mut Self {
        let mut rdata = vec![text.len() as u8];
        rdata.extend_from_slice(text.as_bytes());
        self.raw(owner, ttl, Rtype::TXT, &rdata)
    }

    /// A ZONEMD record from its fields (raw, so that RDATA the typed
    /// view rejects can be built too).
    fn zonemd(
        &mut self,
        owner: &str,
        ttl: u32,
        serial: u32,
        scheme: u8,
        alg: u8,
        digest: &str,
    ) -> &mut Self {
        let mut rdata = serial.to_be_bytes().to_vec();
        rdata.extend([scheme, alg]);
        rdata.extend(hex(digest));
        self.raw(owner, ttl, Rtype::ZONEMD, &rdata)
    }

    #[allow(clippy::too_many_arguments)]
    fn rrsig(
        &mut self,
        owner: &str,
        ttl: u32,
        covered: Rtype,
        labels: u8,
        original_ttl: u32,
        key_tag: u16,
        signer: &str,
        signature: &str,
    ) -> &mut Self {
        let s = name(signer);
        let sig = b64(signature);
        self.add(
            owner,
            ttl,
            Rrsig {
                type_covered: covered,
                algorithm: crate::dnssec::Algorithm::RSASHA256,
                labels,
                original_ttl,
                // 20210217232440 and 20210120232440 (RFC 8976 A.4).
                expiration: 1_613_604_280,
                inception: 1_611_185_080,
                key_tag,
                signer_name: s.as_name(),
                signature: &sig,
            },
        )
    }

    fn nsec(&mut self, owner: &str, ttl: u32, next: &str, types: &[Rtype]) -> &mut Self {
        let n = name(next);
        let mut buf = [0u8; 64];
        let mut w = WireWriter::new(&mut buf);
        TypeBitmap::compose(types, &mut w).unwrap();
        let bitmap = w.as_bytes().to_vec();
        self.add(
            owner,
            ttl,
            Nsec::new(n.as_name(), TypeBitmap::new(&bitmap).unwrap()),
        )
    }

    /// NAPTR with empty flags and services and a root replacement, as in
    /// the URI.ARPA zone.
    fn naptr(&mut self, owner: &str, ttl: u32, regexp: &str) -> &mut Self {
        let mut rdata = vec![0, 0, 0, 0, 0, 0, regexp.len() as u8];
        rdata.extend_from_slice(regexp.as_bytes());
        rdata.push(0);
        self.raw(owner, ttl, Rtype::NAPTR, &rdata)
    }

    fn records(&self) -> Vec<ZonemdRecord<'_, RData<'_>>> {
        self.rrs
            .iter()
            .map(|(owner, ttl, rtype, rdata)| {
                let data = RData::parse(*rtype, Class::IN, WireReader::new(rdata))
                    .unwrap_or(RData::Unknown(UnknownRdata::new(*rtype, rdata)));
                ZonemdRecord::new(owner.as_name(), Class::IN, *ttl, data)
            })
            .collect()
    }

    fn collate(&self, apex: &str) -> ZoneCollation {
        ZoneCollation::new(name(apex).as_name(), self.records()).unwrap()
    }
}

const SOA_EXAMPLE: [u32; 5] = [2018031900, 1800, 900, 604800, 86400];

/// RFC 8976 Appendix A.1.
fn a1() -> Zone {
    let mut z = Zone::default();
    z.soa(
        "example",
        86400,
        "ns1.example",
        "admin.example",
        SOA_EXAMPLE,
    )
    .ns("example", 86400, "ns1.example")
    .ns("example", 86400, "ns2.example")
    .zonemd(
        "example",
        86400,
        2018031900,
        1,
        1,
        "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3
             a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c",
    )
    .a("ns1.example", 3600, "203.0.113.63")
    .aaaa("ns2.example", 3600, "2001:db8::63");
    z
}

/// RFC 8976 Appendix A.2.
fn a2() -> Zone {
    let mut z = Zone::default();
    z.soa(
        "example",
        86400,
        "ns1.example",
        "admin.example",
        SOA_EXAMPLE,
    )
    .ns("example", 86400, "ns1.example")
    .ns("example", 86400, "ns2.example")
    .zonemd(
        "example",
        86400,
        2018031900,
        1,
        1,
        "a3b69bad980a3504e1cffcb0fd6397f93848071c93151f55
             2ae2f6b1711d4bd2d8b39808226d7b9db71e34b72077f8fe",
    )
    .a("ns1.example", 3600, "203.0.113.63")
    .aaaa("NS2.example", 3600, "2001:db8::63")
    .txt(
        "occluded.sub.example",
        7200,
        "I'm occluded but must be digested",
    )
    .ns("sub.example", 7200, "ns1.example")
    .txt("duplicate.example", 300, "I must be digested just once")
    .txt("duplicate.example", 300, "I must be digested just once")
    .txt("foo.test", 555, "out-of-zone data must be excluded")
    .txt(
        "UPPERCASE.example",
        3600,
        "canonicalize uppercase owner names",
    )
    .ptr("*.example", 777, "dont-forget-about-wildcards.example")
    .mx("mail.example", 3600, 20, "MAIL1.example")
    .mx("mail.example", 3600, 10, "Mail2.Example")
    .aaaa("sortme.example", 3600, "2001:db8::5:61")
    .aaaa("sortme.example", 3600, "2001:db8::3:62")
    .aaaa("sortme.example", 3600, "2001:db8::4:63")
    .aaaa("sortme.example", 3600, "2001:db8::1:65")
    .aaaa("sortme.example", 3600, "2001:db8::2:64")
    .zonemd(
        "non-apex.example",
        900,
        2018031900,
        1,
        1,
        "616c6c6f776564206275742069676e6f7265642e20616c6c
             6f776564206275742069676e6f7265642e20616c6c6f7765",
    );
    z
}

/// RFC 8976 Appendix A.3.
fn a3() -> Zone {
    let mut z = Zone::default();
    z.soa(
        "example",
        86400,
        "ns1.example",
        "admin.example",
        SOA_EXAMPLE,
    )
    .ns("example", 86400, "ns1.example")
    .ns("example", 86400, "ns2.example")
    .zonemd(
        "example",
        86400,
        2018031900,
        1,
        1,
        "62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637
             493daaf401c92c279dd10f0edb1c56f8080211f8480ee306",
    )
    .zonemd(
        "example",
        86400,
        2018031900,
        1,
        2,
        "08cfa1115c7b948c4163a901270395ea226a930cd2cbcf2fa9a5e6eb85f37c8a
             4e114d884e66f176eab121cb02db7d652e0cc4827e7a3204f166b47e5613fd27",
    )
    .zonemd(
        "example",
        86400,
        2018031900,
        1,
        240,
        "e2d523f654b9422a96c5a8f44607bbee",
    )
    // Hash algorithm 1 with a 20-octet digest: rejected by the typed
    // view, kept as unknown RDATA here.
    .zonemd(
        "example",
        86400,
        2018031900,
        241,
        1,
        "e1846540e33a9e4189792d18d5d131f605fc283e",
    )
    .a("ns1.example", 3600, "203.0.113.63")
    .txt("ns2.example", 86400, "This example has multiple digests")
    .aaaa("NS2.EXAMPLE", 3600, "2001:db8::63");
    z
}

const URI_SIG_SOA: &str = "GzQw+QzwLDJr13REPGVmpEChjD1D2XlX0ie1DnWHpgaEw1E/dhs3lCN3+BmHd4Kx3tffTRgiyq65HxR6feQ5v7VmAifjyXUYB1DZur1eP5q0Ms2ygCB3byoeMgCNsFS1oKZ2LdzNBRpy3oace8xQn1SpmHGfyrsgg+WbHKCT1dY=";
const URI_ZONEMD_SIG: &str = "QDo4XZcL3HMyn8aAHyCUsu/Tqj4Gkth8xY1EqByOb8XOTwVtA4ZNQORE1siqNqjtJUbeJPtJSbLNqCL7rCq0CzNNnBscv6IIf4gnqJZjlGtHO30ohXtKvEc4z7SU3IASsi6bB3nLmEAyERdYSeU6UBfx8vatQDIRhkgEnnWUTh4=";
const URI_ZONEMD: &str = "0dbc3c4dbfd75777c12ca19c337854b1577799901307c482e9d91d5d15cd934d16319d98e30c4201cf25a1d5a0254960";

/// The URI.ARPA DNSKEYs: (flags, public key).
const URI_DNSKEYS: [(u16, &str); 3] = [
    (
        256,
        "AwEAAbMxuFuLeVDuOwIMzYOTD/bTREjLflo7wOi6ieIJhqltEzgjNzmWJf9kGwwDmzxU7kbthMEhBNBZNn84zmcyRSCMzuStWveL7xmqqUlE3swL8kLOvdZvc75XnmpHrk3ndTyEb6eZM7slh2C63Oh6K8VR5VkiZAkEGg0uZIT3NjsF",
    ),
    (
        257,
        "AwEAAdkTaWkZtZuRh7/OobBUFxM+ytTst+bCu0r9w+rEwXD7GbDs0pIMhMenrZzoAvmv1fQxw2MGs6Ri6yPKfNULcFOSt9l8i6BVBLI+SKTY6XXeDUQpSEmSaxohHeRPMQFzpysfjxINp/L2rGtZ7yPmxY/XRiFPSO0myqwGJa9r06Zw9CHM5UDHKWV/E+zxPFq/I7CfPbrrzbUotBX7Z6Vh3Sarllbe8cGUB2UFNaTRgwB0TwDBPRD5ER3w2Dzbry9NhbElTr7vVfhaGWeOGuqAUXwlXEg6CrNkmJXJ2F1Rzr9WHUzhp7uWxhAbmJREGfi2dEyPAbUAyCjBqhFaqglknvc=",
    ),
    (
        257,
        "AwEAAenQaBoFmDmvRT+/H5oNbm0Tr5FmNRNDEun0Jpj/ELkzeUrTWhNpQmZeIMC8I0kZ185tEvOnRvn8OvV39B17QIdrvvKGIh2HlgeDRCLolhaojfn2QM0DStjF/WWHpxJOmE6CIuvhqYEU37yoJscGAPpPVPzNvnL1HhYTaao1VRYWQ/maMrJ+bfHg+YX1N6M/8MnRjIKBif1FWjbCKvsn6dnuGGL9oCWYUFJ3DwofXuhgPyZMkzPc88YkJj5EMvbMH4wtelbCwC+ivx732l0w/rXJn0ciQSOgoeVvDio8dIJmWQITWQAuP+q/ZHFEFHPlrP3gvQh5mcVS48eLX71Bq7c=",
    ),
];

/// RFC 8976 Appendix A.4: the URI.ARPA zone, DNSSEC-signed.
fn a4() -> Zone {
    use Rtype as T;
    let naptr_types = [T::NAPTR, T::RRSIG, T::NSEC];
    let mut z = Zone::default();
    z.soa(
        "uri.arpa",
        3600,
        "sns.dns.icann.org",
        "noc.dns.icann.org",
        [2018100702, 10800, 3600, 1209600, 3600],
    )
    .rrsig("uri.arpa", 3600, T::SOA, 2, 3600, 37444, "uri.arpa", URI_SIG_SOA)
    .ns("uri.arpa", 86400, "a.iana-servers.net")
    .ns("uri.arpa", 86400, "b.iana-servers.net")
    .ns("uri.arpa", 86400, "c.iana-servers.net")
    .ns("uri.arpa", 86400, "ns2.lacnic.net")
    .ns("uri.arpa", 86400, "sec3.apnic.net")
    .rrsig(
        "uri.arpa",
        86400,
        T::NS,
        2,
        86400,
        37444,
        "uri.arpa",
        "M+Iei2lcewWGaMtkPlrhM9FpUAHXFkCHTVpeyrjxjEONeNgKtHZor5e4V4qJBOzNqo8go/qJpWlFBm+T5Hn3asaBZVstFIYky38/C8UeRLPKq1hTTHARYUlFrexr5fMtSUAVOgOQPSBfH3xBq/BgSccTdRb9clD+HE7djpqrLS4=",
    )
    .mx("uri.arpa", 600, 10, "pechora.icann.org")
    .rrsig(
        "uri.arpa",
        600,
        T::MX,
        2,
        600,
        37444,
        "uri.arpa",
        "kQAJQivmv6A5hqYBK8h6Z13ESY69gmosXwKI6WE09I8RFetfrxr24ecdnYd0lpnDtgNNSoHkYRSOoB+C4+zuJsoyAAzGo9uoWMWj97/2xeGhf3PTC9meQ9Ohi6hul9By7OR76XYmGhdWX8PBi60RUmZ1guslFBfQ8izwPqzuphs=",
    );
    for (flags, key) in URI_DNSKEYS {
        let key = b64(key);
        z.add(
            "uri.arpa",
            3600,
            Dnskey::new(flags, 3, crate::dnssec::Algorithm::RSASHA256, &key),
        );
    }
    z.rrsig(
        "uri.arpa",
        3600,
        T::DNSKEY,
        2,
        3600,
        12670,
        "uri.arpa",
        "DBE2gkKAoxJCfz47KKxzoImN/0AKArhIVHE7TyTwy0DdRPo44V5R+vL6thUxlQ1CJi2Rw0jwAXymx5Y3Q873pOEllH+4bJoIT4dmoBmPXfYWW7Clvw9UPKHRP0igKHmCVwIeBYDTU3gfLcMTbR4nEWPDN0GxlL1Mf7ITaC2Ioabo79Ip3M/MR8I3Vx/xZ4ZKKPHtLn3xUuJluPNanqJrED2gTslL2xWZ1tqjsAjJv7JnJo2HJ8XVRB5zBto0IaJ2oBlqcjdcQ/0VlyoM8uOy1pDwHQ2BJl7322gNMHBP9HSiUPIOaIDNUCwW8eUcW6DIUk+s9u3GN1uTqwWzsYB/rA==",
    )
    .rrsig(
        "uri.arpa",
        3600,
        T::DNSKEY,
        2,
        3600,
        30577,
        "uri.arpa",
        "Kx6HwP4UlkGc1UZ7SERXtQjPajOF4iUvkwDj7MEG1xbQFB1KoJiEb/eiW0qmSWdIhMDv8myhgauejRLyJxwxz8HDRV4xOeHWnRGfWBk4XGYwkejVzOHzoIArVdUVRbr2JKigcTOoyFN+uu52cNB7hRYu7dH5y1hlc6UbOnzRpMtGxcgVyKQ+/ARbIqGG3pegdEOvV49wTPWEiyY65P2urqhvnRg5ok/jzwAdMx4XGshiib7Ojq0sRVl2ZIzj4rFgY/qsSO8SEXEhMo2VuSkoJNiofVzYoqpxEeGnANkIT7Tx2xJL1BWyJxyc7E8Wr2QSgCcc+rYL6IkHDtJGHy7TaQ==",
    )
    .zonemd("uri.arpa", 3600, 2018100702, 1, 1, URI_ZONEMD)
    .rrsig("uri.arpa", 3600, T::ZONEMD, 2, 3600, 37444, "uri.arpa", URI_ZONEMD_SIG)
    .nsec(
        "uri.arpa",
        3600,
        "ftp.uri.arpa",
        &[T::NS, T::SOA, T::MX, T::RRSIG, T::NSEC, T::DNSKEY, T::ZONEMD],
    )
    .rrsig(
        "uri.arpa",
        3600,
        T::NSEC,
        2,
        3600,
        37444,
        "uri.arpa",
        "dU/rXLM/naWd1+1PiWiYVaNJyCkiuyZJSccr91pJI673T8r3685B4ODMYFafZRboVgwnl3ZrXddY6xOhZL3n9V9nxXZwjLJ2HJUojFoKcXTlpnUyYUYvVQ2kj4GHAo6fcGCEp5QFJ2KbCpeJoS+PhKGRRx28icCiNT4/uXQvO2E=",
    )
    .naptr("ftp.uri.arpa", 604800, "!^ftp://([^:/?#]*).*$!\\1!i")
    .rrsig(
        "ftp.uri.arpa",
        604800,
        T::NAPTR,
        3,
        604800,
        37444,
        "uri.arpa",
        "EygekDgl+Lyyq4NMSEpPyOrOywYf9Y3FAB4v1DT44J3R5QGidaH8l7ZFjHoYFI8sY64iYOCV4sBnX/dh6C1L5NgpY+8l5065Xu3vvjyzbtuJ2k6YYwJrrCbvl5DDn53zAhhO2hL9uLgyLraZGi9i7TFGd0sm3zNyUF/EVL0CcxU=",
    )
    .nsec("ftp.uri.arpa", 3600, "http.uri.arpa", &naptr_types)
    .rrsig(
        "ftp.uri.arpa",
        3600,
        T::NSEC,
        3,
        3600,
        37444,
        "uri.arpa",
        "pbP4KxevPXCu/bDqcvXiuBppXyFEmtHyiy0eAN5gS7mi6mp9Z9bWFjx/LdH9+6oFGYa5vGmJ5itu/4EDMe8iQeZbI8yrpM4TquB7RR/MGfBnTd8S+sjyQtlRYG7yqEu77Vd78Fme22BKPJ+MVqjS0JHMUE/YUGomPkAjLJJwwGw=",
    )
    .naptr("http.uri.arpa", 604800, "!^http://([^:/?#]*).*$!\\1!i")
    .rrsig(
        "http.uri.arpa",
        604800,
        T::NAPTR,
        3,
        604800,
        37444,
        "uri.arpa",
        "eTqbWvt1GvTeXozuvm4ebaAfkXFQKrtdu0cEiExto80sHIiCbO0WL8UDa/J3cDivtQca7LgUbOb6c17NESsrsVkc6zNPx5RK2tG7ZQYmhYmtqtfg1oU5BRdHZ5TyqIXcHlw9Blo2pir1Y9IQgshhD7UOGkbkEmvB1Lrd0aHhAAg=",
    )
    .nsec("http.uri.arpa", 3600, "mailto.uri.arpa", &naptr_types)
    .rrsig(
        "http.uri.arpa",
        3600,
        T::NSEC,
        3,
        3600,
        37444,
        "uri.arpa",
        "R9rlNzw1CVz2N08q6DhULzcsuUm0UKcPaGAWEU40tr81jEDHsFHNM+khCdOI8nDstzA42aee4rwCEgijxJpRCcY9hrO1Ysrrr2fdqNz60JikMdarvU5O0p0VXeaaJDfJQT44+o+YXaBwI7Qod3FTMx7aRib8i7istvPm1Rr7ixA=",
    )
    .naptr("mailto.uri.arpa", 604800, "!^mailto:(.*)@(.*)$!\\2!i")
    .rrsig(
        "mailto.uri.arpa",
        604800,
        T::NAPTR,
        3,
        604800,
        37444,
        "uri.arpa",
        "Ch2zTG2F1plEvQPyIH4Yd80XXLjXOPvMbiqDjpJBcnCJsV8QF7kr0wTLnUT3dB+asQudOjPyzaHGwFlMzmrrAsszN4XAMJ6htDtFJdsgTMP/NkHhYRSmVv6rLeAhd+mVfObY12M//b/GGVTjeUI/gJaLW0fLVZxr1Fp5U5CRjyw=",
    )
    .nsec("mailto.uri.arpa", 3600, "urn.uri.arpa", &naptr_types)
    .rrsig(
        "mailto.uri.arpa",
        3600,
        T::NSEC,
        3,
        3600,
        37444,
        "uri.arpa",
        "fQUbSIE6E7JDi2rosah4SpCOTrKufeszFyj5YEavbQuYlQ5cNFvtm8KuE2xXMRgRI4RGvM2leVqcoDw5hS3m2pOJLxH8l2WE72YjYvWhvnwc5Rofe/8yB/vaSK9WCnqN8y2q6Vmy73AGP0fuiwmuBra7LlkOiqmyx3amSFizwms=",
    )
    .naptr("urn.uri.arpa", 604800, "/urn:([^:]+)/\\1/i")
    .rrsig(
        "urn.uri.arpa",
        604800,
        T::NAPTR,
        3,
        604800,
        37444,
        "uri.arpa",
        "CVt2Tgz0e5ZmaSXqRfNys/8OtVCk9nfP0zhezhN8Bo6MDt6yyKZ2kEEWJPjkN7PCYHjO8fGjnUn0AHZI2qBNv7PKHcpR42VY03q927q85a65weOO1YE0vPYMzACpua9TOtfNnynM2Ws0uN9URxUyvYkXBdqOC81N3sx1dVELcwc=",
    )
    .nsec("urn.uri.arpa", 3600, "uri.arpa", &naptr_types)
    .rrsig(
        "urn.uri.arpa",
        3600,
        T::NSEC,
        3,
        3600,
        37444,
        "uri.arpa",
        "JuKkMiC3/j9iM3V8/izcouXWAVGnSZjkOgEgFPhutMqoylQNRcSkbEZQzFK8B/PIVdzZF0Y5xkO6zaKQjOzz6OkSaNPIo1a7Vyyl3wDY/uLCRRAHRJfpknuY7O+AUNXvVVIEYJqZggd4kl/Rjh1GTzPYZTRrVi5eQidI1LqCOeg=",
    );
    z
}

/// RFC 8976 Appendix A.5: the ROOT-SERVERS.NET zone (with its SOA twice).
fn a5() -> Zone {
    const TTL: u32 = 3600000;
    let soa = [2018091100, 14400, 7200, 1209600, 3600000];
    let mut z = Zone::default();
    z.soa(
        "root-servers.net",
        TTL,
        "a.root-servers.net",
        "nstld.verisign-grs.com",
        soa,
    );
    for l in 'a'..='m' {
        z.ns(
            "root-servers.net",
            TTL,
            &std::format!("{l}.root-servers.net"),
        );
    }
    let hosts = [
        ("a", "2001:503:ba3e::2:30", "198.41.0.4"),
        ("b", "2001:500:200::b", "199.9.14.201"),
        ("c", "2001:500:2::c", "192.33.4.12"),
        ("d", "2001:500:2d::d", "199.7.91.13"),
        ("e", "2001:500:a8::e", "192.203.230.10"),
        ("f", "2001:500:2f::f", "192.5.5.241"),
        ("g", "2001:500:12::d0d", "192.112.36.4"),
        ("h", "2001:500:1::53", "198.97.190.53"),
        ("i", "2001:7fe::53", "192.36.148.17"),
        ("j", "2001:503:c27::2:30", "192.58.128.30"),
        ("k", "2001:7fd::1", "193.0.14.129"),
        ("l", "2001:500:9f::42", "199.7.83.42"),
        ("m", "2001:dc3::35", "202.12.27.33"),
    ];
    for (l, v6, v4) in hosts {
        let owner = std::format!("{l}.root-servers.net");
        match l {
            "b" => {
                z.mx(&owner, TTL, 20, "mail.isi.edu");
            }
            "i" => {
                z.mx(&owner, TTL, 10, "mx.i.root-servers.org");
            }
            _ => {}
        }
        z.aaaa(&owner, TTL, v6).a(&owner, TTL, v4);
    }
    z.soa(
        "root-servers.net",
        TTL,
        "a.root-servers.net",
        "nstld.verisign-grs.com",
        soa,
    )
    .zonemd(
        "root-servers.net",
        TTL,
        2018091100,
        1,
        1,
        "f1ca0ccd91bd5573d9f431c00ee0101b2545c97602be0a97
         8a3b11dbfc1c776d5b3e86ae3d973d6b5349ba7f04340f79",
    );
    z
}

/// The owner names of the collated RRs, in order.
fn owners(c: &ZoneCollation) -> Vec<String> {
    c.rrs()
        .map(|rr| {
            WireReader::new(rr)
                .read_name_uncompressed()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[test]
fn collation_rules() {
    // RFC 8976 A.2: duplicates once, out-of-zone excluded, apex ZONEMD
    // excluded, non-apex ZONEMD, occluded data and glue included, owners
    // lowercased, canonical order.
    let c = a2().collate("example");
    assert_eq!(c.apex(), name("example").as_name());
    assert_eq!(c.len(), 18);
    assert!(!c.is_empty());
    assert_eq!(
        owners(&c),
        [
            "example.",
            "example.",
            "example.",
            "*.example.",
            "duplicate.example.",
            "mail.example.",
            "mail.example.",
            "non-apex.example.",
            "ns1.example.",
            "ns2.example.",
            "sortme.example.",
            "sortme.example.",
            "sortme.example.",
            "sortme.example.",
            "sortme.example.",
            "sub.example.",
            "occluded.sub.example.",
            "uppercase.example.",
        ]
    );
    // RRsets of a name by type (NS = 2 before SOA = 6), RRs by RDATA in
    // canonical form: MX 10 before MX 20 (names lowercased), the AAAA
    // records by address.
    let types: Vec<Rtype> = c.entries.iter().map(|e| c.rtype(e)).collect();
    assert_eq!(&types[..3], [Rtype::NS, Rtype::NS, Rtype::SOA]);
    let mail: Vec<&[u8]> = c
        .entries
        .iter()
        .skip(5)
        .take(2)
        .map(|e| c.rdata(e))
        .collect();
    assert_eq!(mail[0], b"\x00\x0a\x05mail2\x07example\x00");
    assert_eq!(mail[1], b"\x00\x14\x05mail1\x07example\x00");
    let sortme: Vec<u8> = c
        .entries
        .iter()
        .skip(10)
        .take(5)
        .map(|e| c.rdata(e)[15])
        .collect();
    assert_eq!(sortme, [0x65, 0x64, 0x62, 0x63, 0x61]);
    assert_eq!(c.soa_serial(), Some(2018031900));
    assert_eq!(c.zonemd_rdata().count(), 1);

    // The input order does not matter.
    let mut reversed = a2();
    reversed.rrs.reverse();
    let r = reversed.collate("example");
    assert!(c.rrs().eq(r.rrs()));
    // Neither does the apex's case.
    let upper = a2().collate("EXAMPLE");
    assert!(c.rrs().eq(upper.rrs()));
}

#[test]
fn apex_rrsig_over_zonemd_excluded() {
    // RFC 8976 §3.3.1.1: the RRSIG covering the apex ZONEMD RRset is not
    // digested, other RRSIGs are, as is an RRSIG over a non-apex ZONEMD.
    let c = a4().collate("uri.arpa");
    let rrsigs = c
        .entries
        .iter()
        .filter(|e| c.rtype(e) == Rtype::RRSIG)
        .count();
    assert_eq!(rrsigs, 14);
    assert_eq!(c.zonemd_rdata().count(), 1);
    let mut z = a1();
    z.rrsig(
        "ns1.example",
        3600,
        Rtype::ZONEMD,
        2,
        3600,
        1,
        "example",
        "AAAA",
    );
    assert_eq!(z.collate("example").len(), 6);
}

#[test]
fn multiple_zonemd_and_duplicate_soa() {
    // RFC 8976 A.3: four apex ZONEMD RRs kept aside, in input order (the
    // last one as unknown RDATA: its digest is too short for SHA-384).
    let c = a3().collate("example");
    assert_eq!(c.len(), 6);
    let tuples: Vec<(u8, u8)> = c.zonemd_rdata().map(|rd| (rd[4], rd[5])).collect();
    assert_eq!(tuples, [(1, 1), (1, 2), (1, 240), (241, 1)]);
    // RFC 8976 A.5: the SOA appears twice in the zone, once in the digest.
    let c = a5().collate("root-servers.net");
    assert_eq!(c.len(), 1 + 13 + 26 + 2);
    assert_eq!(c.soa_serial(), Some(2018091100));
}

#[test]
fn soa_serial() {
    let mut z = Zone::default();
    z.a("www.example", 60, "192.0.2.1");
    assert_eq!(z.collate("example").soa_serial(), None);
    // A non-apex SOA does not count.
    z.soa(
        "sub.example",
        60,
        "ns.example",
        "admin.example",
        SOA_EXAMPLE,
    );
    assert_eq!(z.collate("example").soa_serial(), None);
    // Two different apex SOAs are ambiguous; identical ones are one RR.
    z.soa("example", 60, "ns.example", "admin.example", SOA_EXAMPLE);
    assert_eq!(z.collate("example").soa_serial(), Some(2018031900));
    z.soa("example", 120, "ns.example", "admin.example", SOA_EXAMPLE);
    assert_eq!(z.collate("example").soa_serial(), Some(2018031900));
    z.soa(
        "example",
        60,
        "ns.example",
        "admin.example",
        [1, 2, 3, 4, 5],
    );
    assert_eq!(z.collate("example").soa_serial(), None);
}

/// RDATA that fails to encode.
struct Broken;

impl ComposeRdata for Broken {
    fn rtype(&self) -> Rtype {
        Rtype::TXT
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, _: &mut C) -> Result<()> {
        Err(Error::InvalidRdata)
    }
}

/// RDATA longer than 65535 octets.
struct Huge;

impl ComposeRdata for Huge {
    fn rtype(&self) -> Rtype {
        Rtype::NULL
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(&vec![0; 70_000])
    }
}

#[test]
fn encoding_errors() {
    let apex = name("example");
    let broken = ZonemdRecord::new(apex.as_name(), Class::IN, 0, Broken);
    assert_eq!(
        ZoneCollation::new(apex.as_name(), [broken]).err(),
        Some(Error::InvalidRdata)
    );
    let huge = ZonemdRecord::new(apex.as_name(), Class::IN, 0, Huge);
    assert_eq!(
        ZoneCollation::new(apex.as_name(), [huge]).err(),
        Some(Error::BufferTooSmall)
    );
    // Out-of-zone records are not even encoded.
    let other = name("test");
    let c = ZoneCollation::new(
        apex.as_name(),
        [ZonemdRecord::new(other.as_name(), Class::IN, 0, Broken)],
    )
    .unwrap();
    assert!(c.is_empty());
}

#[cfg(feature = "dnssec-digest")]
mod digest {
    use super::*;
    use crate::MessageBuilder;

    fn digest_of(z: &Zone, apex: &str, alg: ZonemdHashAlg) -> Vec<u8> {
        z.collate(apex).digest(alg).unwrap().as_bytes().to_vec()
    }

    fn verified(serial: u32, hash_alg: ZonemdHashAlg) -> ZonemdVerified {
        ZonemdVerified {
            serial,
            scheme: ZonemdScheme::SIMPLE,
            hash_alg,
        }
    }

    #[test]
    fn rfc8976_a1_simple() {
        let z = a1();
        let c = z.collate("example");
        assert_eq!(c.len(), 5);
        let d = c.digest(ZonemdHashAlg::SHA384).unwrap();
        assert_eq!(d.hash_alg(), ZonemdHashAlg::SHA384);
        assert_eq!(
            d.as_bytes(),
            hex("c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3
                 a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c")
        );
        let zonemd = d.to_zonemd(2018031900);
        assert_eq!(zonemd.validate(), Ok(()));
        assert_eq!(zonemd.scheme, ZonemdScheme::SIMPLE);
        assert_eq!(c.verify(), Ok(verified(2018031900, ZonemdHashAlg::SHA384)));
        // The free functions.
        let apex = name("example");
        assert_eq!(
            zonemd_digest(apex.as_name(), z.records(), ZonemdHashAlg::SHA384),
            Ok(d)
        );
        assert_eq!(
            verify_zonemd(apex.as_name(), z.records()),
            Ok(verified(2018031900, ZonemdHashAlg::SHA384))
        );
        assert_eq!(
            c.digest(ZonemdHashAlg::new(3)),
            Err(Error::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn rfc8976_a2_complex() {
        let z = a2();
        assert_eq!(
            digest_of(&z, "example", ZonemdHashAlg::SHA384),
            hex("a3b69bad980a3504e1cffcb0fd6397f93848071c93151f55
                 2ae2f6b1711d4bd2d8b39808226d7b9db71e34b72077f8fe")
        );
        assert_eq!(
            z.collate("example").verify(),
            Ok(verified(2018031900, ZonemdHashAlg::SHA384))
        );
    }

    #[test]
    fn rfc8976_a3_multiple_digests() {
        let z = a3();
        let c = z.collate("example");
        assert_eq!(c.zonemd_rdata().count(), 4);
        assert_eq!(
            c.digest(ZonemdHashAlg::SHA384).unwrap().as_bytes(),
            hex("62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637
                 493daaf401c92c279dd10f0edb1c56f8080211f8480ee306")
        );
        assert_eq!(
            c.digest(ZonemdHashAlg::SHA512).unwrap().as_bytes(),
            hex(
                "08cfa1115c7b948c4163a901270395ea226a930cd2cbcf2fa9a5e6eb85f37c8a
                 4e114d884e66f176eab121cb02db7d652e0cc4827e7a3204f166b47e5613fd27"
            )
        );
        assert_eq!(c.verify(), Ok(verified(2018031900, ZonemdHashAlg::SHA384)));
        // With only the SHA-512 and private-range RRs, SHA-512 verifies.
        let keep = |f: &dyn Fn(&[u8]) -> bool| Zone {
            rrs: z
                .rrs
                .iter()
                .filter(|(_, _, t, rd)| *t != Rtype::ZONEMD || f(rd))
                .cloned()
                .collect(),
        };
        let only512 = keep(&|rd| rd.get(5) != Some(&1));
        assert_eq!(
            only512.collate("example").verify(),
            Ok(verified(2018031900, ZonemdHashAlg::SHA512))
        );
        // With only the private-range ones, nothing does: the failure of
        // the RR that got furthest is reported.
        let private = keep(&|rd| rd.get(5) == Some(&240) || rd.get(4) == Some(&241));
        assert_eq!(
            private.collate("example").verify(),
            Err(ZonemdFailure::UnsupportedHashAlgorithm)
        );
    }

    #[test]
    fn rfc8976_a4_uri_arpa() {
        let z = a4();
        let c = z.collate("uri.arpa");
        assert_eq!(
            c.digest(ZonemdHashAlg::SHA384).unwrap().as_bytes(),
            hex(URI_ZONEMD)
        );
        assert_eq!(c.verify(), Ok(verified(2018100702, ZonemdHashAlg::SHA384)));
    }

    /// RFC 8976 §4 step 3: the ZONEMD RRset of a signed zone must be
    /// validated; the URI.ARPA RRSIG over it verifies with the zone's ZSK.
    #[cfg(feature = "dnssec")]
    #[test]
    fn rfc8976_a4_zonemd_signature() {
        use crate::dnssec::{Algorithm, PurecryptoVerifier, Rrset, TrustedKeys};
        use crate::rdata::Zonemd;
        let apex = name("uri.arpa");
        let keys: Vec<Vec<u8>> = URI_DNSKEYS.iter().map(|(_, k)| b64(k)).collect();
        let dnskeys: Vec<Dnskey<'_>> = URI_DNSKEYS
            .iter()
            .zip(&keys)
            .map(|((flags, _), k)| Dnskey::new(*flags, 3, Algorithm::RSASHA256, k))
            .collect();
        assert!(dnskeys.iter().any(|k| k.key_tag() == 37444));
        let trusted =
            TrustedKeys::assume_trusted(apex.as_name(), Class::IN, dnskeys.iter().copied());
        let digest = hex(URI_ZONEMD);
        let zonemd = [Zonemd {
            serial: 2018100702,
            scheme: ZonemdScheme::SIMPLE,
            hash_alg: ZonemdHashAlg::SHA384,
            digest: &digest,
        }];
        let sig = b64(URI_ZONEMD_SIG);
        let rrsig = Rrsig {
            type_covered: Rtype::ZONEMD,
            algorithm: Algorithm::RSASHA256,
            labels: 2,
            original_ttl: 3600,
            expiration: 1_613_604_280,
            inception: 1_611_185_080,
            key_tag: 37444,
            signer_name: apex.as_name(),
            signature: &sig,
        };
        let mut scratch = Vec::new();
        let now = 1_612_000_000;
        let rrset = Rrset::new(apex.as_name(), Class::IN, &zonemd);
        let v = trusted
            .verify_rrset(&PurecryptoVerifier, rrset, [rrsig], now, &mut scratch)
            .unwrap();
        assert_eq!(v.key_tag, 37444);
        // And the SOA RRset.
        let soa_sig = b64(URI_SIG_SOA);
        let (m, r) = (name("sns.dns.icann.org"), name("noc.dns.icann.org"));
        let soa = [Soa {
            mname: m.as_name(),
            rname: r.as_name(),
            serial: 2018100702,
            refresh: 10800,
            retry: 3600,
            expire: 1209600,
            minimum: 3600,
        }];
        let soa_rrsig = Rrsig {
            type_covered: Rtype::SOA,
            signature: &soa_sig,
            ..rrsig
        };
        let rrset = Rrset::new(apex.as_name(), Class::IN, &soa);
        assert!(
            trusted
                .verify_rrset(&PurecryptoVerifier, rrset, [soa_rrsig], now, &mut scratch)
                .is_ok()
        );
    }

    #[test]
    fn rfc8976_a5_root_servers() {
        let z = a5();
        let c = z.collate("root-servers.net");
        // The duplicate SOA is digested once.
        assert_eq!(c.len(), 1 + 13 + 26 + 2);
        assert_eq!(c.soa_serial(), Some(2018091100));
        assert_eq!(
            c.digest(ZonemdHashAlg::SHA384).unwrap().as_bytes(),
            hex("f1ca0ccd91bd5573d9f431c00ee0101b2545c97602be0a97
                 8a3b11dbfc1c776d5b3e86ae3d973d6b5349ba7f04340f79")
        );
        assert_eq!(c.verify(), Ok(verified(2018091100, ZonemdHashAlg::SHA384)));
    }

    #[test]
    fn from_zone_transfer() {
        // The A.1 zone as an AXFR response (SOA first and last), read
        // through message records.
        let z = a1();
        let mut records = z.records();
        records.push(records[0].clone());
        let mut b = MessageBuilder::new_vec();
        for r in &records {
            b.push_answer(r.name, r.class, r.ttl, &r.data).unwrap();
        }
        let wire = b.finish();
        let msg = crate::Message::parse(&wire).unwrap();
        let apex = name("example");
        let rrs = msg.answers().map(|rr| ZonemdRecord::from(rr.unwrap()));
        assert_eq!(
            verify_zonemd(apex.as_name(), rrs),
            Ok(verified(2018031900, ZonemdHashAlg::SHA384))
        );
    }

    #[test]
    fn verification_failures() {
        let apex = "example";
        let base = || {
            let mut z = a1();
            z.rrs.retain(|(_, _, t, _)| *t != Rtype::ZONEMD);
            z
        };
        let good = "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3
                    a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c";
        let check = |f: &dyn Fn(&mut Zone)| {
            let mut z = base();
            f(&mut z);
            z.collate(apex).verify()
        };
        // No ZONEMD, no SOA.
        assert_eq!(check(&|_| {}), Err(ZonemdFailure::NoZonemd));
        assert_eq!(
            check(&|z| {
                z.rrs.retain(|(_, _, t, _)| *t != Rtype::SOA);
                z.zonemd(apex, 0, 2018031900, 1, 1, good);
            }),
            Err(ZonemdFailure::NoSoa)
        );
        // A non-apex ZONEMD does not count.
        assert_eq!(
            check(&|z| {
                z.zonemd("ns1.example", 0, 2018031900, 1, 1, good);
            }),
            Err(ZonemdFailure::NoZonemd)
        );
        // Step 5a-5f.
        assert_eq!(
            check(&|z| {
                z.zonemd(apex, 0, 2018031901, 1, 1, good);
            }),
            Err(ZonemdFailure::SerialMismatch)
        );
        assert_eq!(
            check(&|z| {
                z.zonemd(apex, 0, 2018031900, 2, 1, good);
            }),
            Err(ZonemdFailure::UnsupportedScheme)
        );
        assert_eq!(
            check(&|z| {
                z.zonemd(apex, 0, 2018031900, 1, 3, good);
            }),
            Err(ZonemdFailure::UnsupportedHashAlgorithm)
        );
        assert_eq!(
            check(&|z| {
                z.zonemd(apex, 0, 2018031900, 1, 2, good);
            }),
            Err(ZonemdFailure::DigestLength)
        );
        assert_eq!(
            check(&|z| {
                z.zonemd(apex, 0, 2018031900, 1, 1, "00112233445566778899aabb");
            }),
            Err(ZonemdFailure::DigestLength)
        );
        assert_eq!(
            check(&|z| {
                z.zonemd(apex, 0, 2018031900, 1, 1, good);
                z.a("ns3.example", 3600, "203.0.113.64");
            }),
            Err(ZonemdFailure::DigestMismatch)
        );
        // Changing a TTL changes the digest too.
        assert_eq!(
            check(&|z| {
                z.zonemd(apex, 0, 2018031900, 1, 1, good);
                z.rrs[4].1 = 3601;
            }),
            Err(ZonemdFailure::DigestMismatch)
        );
        // Malformed RDATA.
        assert_eq!(
            check(&|z| {
                z.raw(apex, 0, Rtype::ZONEMD, &[0, 1, 2, 3, 4]);
            }),
            Err(ZonemdFailure::BadZonemd)
        );
        // Step 4: the same scheme and algorithm twice.
        assert_eq!(
            check(&|z| {
                z.zonemd(apex, 0, 2018031900, 1, 1, good);
                z.zonemd(apex, 0, 2018031900, 1, 1, &"00".repeat(48));
            }),
            Err(ZonemdFailure::DuplicateTuple)
        );
        // An identical duplicate is one RR.
        assert_eq!(
            check(&|z| {
                z.zonemd(apex, 0, 2018031900, 1, 1, good);
                z.zonemd(apex, 0, 2018031900, 1, 1, good);
            }),
            Ok(verified(2018031900, ZonemdHashAlg::SHA384))
        );
        // A bad RR next to a good one does not matter, whatever the order.
        for bad_first in [false, true] {
            assert_eq!(
                check(&|z| {
                    if bad_first {
                        z.zonemd(apex, 0, 1, 1, 2, &"00".repeat(64));
                    }
                    z.zonemd(apex, 0, 2018031900, 1, 1, good);
                    if !bad_first {
                        z.zonemd(apex, 0, 1, 1, 2, &"00".repeat(64));
                    }
                }),
                Ok(verified(2018031900, ZonemdHashAlg::SHA384))
            );
        }
        // Failing to collate.
        let apex = name(apex);
        let broken = || [ZonemdRecord::new(apex.as_name(), Class::IN, 0, Broken)];
        assert_eq!(
            verify_zonemd(apex.as_name(), broken()),
            Err(ZonemdFailure::Malformed(Error::InvalidRdata))
        );
        assert_eq!(
            zonemd_digest(apex.as_name(), broken(), ZonemdHashAlg::SHA384).err(),
            Some(Error::InvalidRdata)
        );
    }

    #[test]
    fn failure_display() {
        for f in [
            ZonemdFailure::Malformed(Error::InvalidRdata),
            ZonemdFailure::NoSoa,
            ZonemdFailure::NoZonemd,
            ZonemdFailure::BadZonemd,
            ZonemdFailure::DuplicateTuple,
            ZonemdFailure::SerialMismatch,
            ZonemdFailure::UnsupportedScheme,
            ZonemdFailure::UnsupportedHashAlgorithm,
            ZonemdFailure::DigestLength,
            ZonemdFailure::DigestMismatch,
        ] {
            assert!(!f.to_string().is_empty());
        }
        assert_eq!(
            ZonemdFailure::DigestMismatch.to_string(),
            "ZONEMD digest mismatch"
        );
    }
}
