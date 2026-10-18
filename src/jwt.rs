//! `private_key_jwt` client authentication (OpenID Connect Core section 9,
//! RFC 7523 section 2.2): a JWT signed with the client's private key, checked
//! against the public keys of its Client ID Metadata Document (`jwks` or
//! `jwks_uri`). Algorithms: RS256, PS256, ES256 (aws-lc-rs, already the TLS
//! provider of reqwest/rustls).

use crate::oauth::canonical_uri;
use aws_lc_rs::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::Deserialize;

pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub const ALGS: &[&str] = &["RS256", "PS256", "ES256"];
/// Clock skew tolerated on `exp`, `nbf` and `iat`.
const SKEW: u64 = 60;
/// Longest accepted assertion lifetime (`exp` this far in the future at most);
/// bounds the replay cache.
pub const MAX_LIFETIME: u64 = 3600;
const MAX_JWT_LEN: usize = 16 * 1024;

/// One JSON Web Key (RFC 7517); only the members needed for RSA and P-256.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

/// Keys of a JWK Set (`{"keys":[...]}`); members that are not usable JWKs
/// are skipped.
pub fn parse_jwks(v: &serde_json::Value) -> Option<Vec<Jwk>> {
    let keys = v.get("keys")?.as_array()?;
    Some(
        keys.iter()
            .filter_map(|k| serde_json::from_value::<Jwk>(k.clone()).ok())
            .take(32)
            .collect(),
    )
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crit: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct Claims {
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    #[serde(default)]
    pub exp: Option<f64>,
    #[serde(default)]
    pub nbf: Option<f64>,
    #[serde(default)]
    pub iat: Option<f64>,
    #[serde(default)]
    pub jti: Option<String>,
}

#[derive(Debug)]
pub struct Assertion {
    header: Header,
    pub claims: Claims,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum SigError {
    /// No key with the `kid` of the header: the client may have rotated keys.
    UnknownKey,
    Invalid(&'static str),
}

/// Split and decode a compact JWS; nothing is verified yet.
pub fn parse(jwt: &str) -> Result<Assertion, &'static str> {
    if jwt.len() > MAX_JWT_LEN {
        return Err("client assertion too long");
    }
    let mut parts = jwt.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("client assertion is not a compact JWS");
    };
    let header: Header = B64
        .decode(h)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("bad client assertion header")?;
    let claims: Claims = B64
        .decode(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("bad client assertion claims")?;
    let signature = B64
        .decode(s)
        .map_err(|_| "bad client assertion signature")?;
    Ok(Assertion {
        header,
        claims,
        signing_input: format!("{h}.{p}").into_bytes(),
        signature,
    })
}

fn b64_uint(s: Option<&str>) -> Option<Vec<u8>> {
    let mut v = B64.decode(s?).ok()?;
    let lead = v.iter().take_while(|b| **b == 0).count();
    v.drain(..lead);
    (!v.is_empty()).then_some(v)
}

fn verify_with(alg: &str, k: &Jwk, msg: &[u8], sig: &[u8]) -> bool {
    match alg {
        "RS256" | "PS256" => {
            let (Some(n), Some(e)) = (b64_uint(k.n.as_deref()), b64_uint(k.e.as_deref())) else {
                return false;
            };
            let params = if alg == "RS256" {
                &signature::RSA_PKCS1_2048_8192_SHA256
            } else {
                &signature::RSA_PSS_2048_8192_SHA256
            };
            RsaPublicKeyComponents { n: &n, e: &e }
                .verify(params, msg, sig)
                .is_ok()
        }
        "ES256" => {
            let (Some(x), Some(y)) = (
                k.x.as_deref().and_then(|x| B64.decode(x).ok()),
                k.y.as_deref().and_then(|y| B64.decode(y).ok()),
            ) else {
                return false;
            };
            if x.len() != 32 || y.len() != 32 {
                return false;
            }
            let mut point = Vec::with_capacity(65);
            point.push(4);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &point)
                .verify(msg, sig)
                .is_ok()
        }
        _ => false,
    }
}

fn key_fits(alg: &str, k: &Jwk) -> bool {
    let kty_ok = match alg {
        "RS256" | "PS256" => k.kty == "RSA",
        "ES256" => k.kty == "EC" && k.crv.as_deref() == Some("P-256"),
        _ => false,
    };
    kty_ok
        && k.alg.as_deref().is_none_or(|a| a == alg)
        && k.use_.as_deref().is_none_or(|u| u == "sig")
}

impl Assertion {
    /// Signature check against `keys` (only `kid` matches if the header has one).
    pub fn verify_signature(&self, keys: &[Jwk]) -> Result<(), SigError> {
        let alg = self.header.alg.as_str();
        if !ALGS.contains(&alg) {
            return Err(SigError::Invalid("unsupported client assertion alg"));
        }
        if self.header.crit.is_some() {
            return Err(SigError::Invalid("unsupported crit header"));
        }
        let kid = self.header.kid.as_deref();
        let candidates: Vec<&Jwk> = keys
            .iter()
            .filter(|k| kid.is_none_or(|kid| k.kid.as_deref() == Some(kid)))
            .filter(|k| key_fits(alg, k))
            .collect();
        if candidates.is_empty() {
            return Err(if kid.is_some() {
                SigError::UnknownKey
            } else {
                SigError::Invalid("no key for the client assertion alg")
            });
        }
        if candidates
            .iter()
            .any(|k| verify_with(alg, k, &self.signing_input, &self.signature))
        {
            Ok(())
        } else {
            Err(SigError::Invalid("client assertion signature invalid"))
        }
    }

    /// RFC 7523 section 3: `iss` and `sub` are the client_id, `aud` names
    /// this authorization server (issuer or token endpoint), unexpired.
    pub fn check_claims(
        &self,
        client_id: &str,
        audiences: &[&str],
        now: u64,
    ) -> Result<(), &'static str> {
        let c = &self.claims;
        if c.iss.as_deref() != Some(client_id) || c.sub.as_deref() != Some(client_id) {
            return Err("client assertion iss and sub must be the client_id");
        }
        let auds: Vec<&str> = match &c.aud {
            Some(serde_json::Value::String(s)) => vec![s.as_str()],
            Some(serde_json::Value::Array(a)) => a.iter().filter_map(|v| v.as_str()).collect(),
            _ => vec![],
        };
        let ok_aud: Vec<String> = audiences.iter().map(|a| canonical_uri(a)).collect();
        if !auds.iter().any(|a| ok_aud.contains(&canonical_uri(a))) {
            return Err("client assertion aud is not this authorization server");
        }
        let now_f = now as f64;
        let skew = SKEW as f64;
        match c.exp {
            Some(exp) if exp + skew > now_f && exp <= now_f + (MAX_LIFETIME + SKEW) as f64 => {}
            Some(exp) if exp + skew <= now_f => return Err("client assertion expired"),
            Some(_) => return Err("client assertion lives too long"),
            None => return Err("client assertion without exp"),
        }
        if c.nbf.is_some_and(|t| t > now_f + skew) || c.iat.is_some_and(|t| t > now_f + skew) {
            return Err("client assertion not valid yet");
        }
        if c.jti
            .as_deref()
            .is_some_and(|j| j.is_empty() || j.len() > 256)
        {
            return Err("bad client assertion jti");
        }
        Ok(())
    }
}

/// `sub` of an unverified assertion (client_id when the form omits it).
pub fn unverified_subject(jwt: &str) -> Option<String> {
    parse(jwt).ok()?.claims.sub
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair};
    use serde_json::json;

    /// Test signer: an RSA or P-256 key pair and its public JWK.
    pub(crate) enum Signer {
        Rsa(RsaKeyPair, &'static str),
        Ec(EcdsaKeyPair),
    }

    impl Signer {
        pub(crate) fn rsa(alg: &'static str) -> Self {
            Signer::Rsa(
                RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap(),
                alg,
            )
        }

        pub(crate) fn es256() -> Self {
            Signer::Ec(EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_FIXED_SIGNING).unwrap())
        }

        pub(crate) fn alg(&self) -> &'static str {
            match self {
                Signer::Rsa(_, a) => a,
                Signer::Ec(_) => "ES256",
            }
        }

        pub(crate) fn jwk(&self, kid: &str) -> serde_json::Value {
            match self {
                Signer::Rsa(k, alg) => {
                    let (n, e) = rsa_public_der(k.public_key().as_ref());
                    json!({"kty":"RSA","kid":kid,"use":"sig","alg":alg,"n":B64.encode(n),"e":B64.encode(e)})
                }
                Signer::Ec(k) => {
                    let p = k.public_key().as_ref();
                    json!({"kty":"EC","kid":kid,"crv":"P-256","x":B64.encode(&p[1..33]),"y":B64.encode(&p[33..65])})
                }
            }
        }

        pub(crate) fn sign(&self, kid: Option<&str>, claims: &serde_json::Value) -> String {
            let mut h = json!({"alg": self.alg(), "typ": "JWT"});
            if let Some(k) = kid {
                h["kid"] = json!(k);
            }
            let input = format!(
                "{}.{}",
                B64.encode(h.to_string()),
                B64.encode(claims.to_string())
            );
            let sig = match self {
                Signer::Rsa(k, alg) => {
                    let mut s = vec![0u8; k.public_modulus_len()];
                    let enc: &'static dyn signature::RsaEncoding = if *alg == "RS256" {
                        &signature::RSA_PKCS1_SHA256
                    } else {
                        &signature::RSA_PSS_SHA256
                    };
                    k.sign(enc, &SystemRandom::new(), input.as_bytes(), &mut s)
                        .unwrap();
                    s
                }
                Signer::Ec(k) => k
                    .sign(&SystemRandom::new(), input.as_bytes())
                    .unwrap()
                    .as_ref()
                    .to_vec(),
            };
            format!("{input}.{}", B64.encode(sig))
        }
    }

    /// (n, e) of a DER `RSAPublicKey` (RFC 8017): SEQUENCE { INTEGER, INTEGER }.
    fn rsa_public_der(der: &[u8]) -> (&[u8], &[u8]) {
        fn tlv(b: &[u8], tag: u8) -> (&[u8], &[u8]) {
            assert_eq!(b[0], tag);
            let (len, hdr) = if b[1] < 0x80 {
                (b[1] as usize, 2)
            } else {
                let k = (b[1] & 0x7f) as usize;
                (
                    b[2..2 + k].iter().fold(0usize, |a, x| a << 8 | *x as usize),
                    2 + k,
                )
            };
            (&b[hdr..hdr + len], &b[hdr + len..])
        }
        let (seq, _) = tlv(der, 0x30);
        let (n, rest) = tlv(seq, 0x02);
        let (e, _) = tlv(rest, 0x02);
        (n, e)
    }

    pub(crate) fn claims(client_id: &str, aud: &str, now: u64) -> serde_json::Value {
        json!({"iss":client_id,"sub":client_id,"aud":aud,"exp":now + 300,"iat":now,"jti":format!("j-{now}-{}", B64.encode(crate::oauth::tests::rand_bytes(6)))})
    }

    fn keys(v: serde_json::Value) -> Vec<Jwk> {
        parse_jwks(&json!({ "keys": [v] })).unwrap()
    }

    #[test]
    fn signatures_all_algs() {
        let cid = "https://client.example/cimd.json";
        let aud = "https://as.example/oauth/token";
        for s in [Signer::rsa("RS256"), Signer::rsa("PS256"), Signer::es256()] {
            let jwt = s.sign(Some("k1"), &claims(cid, aud, 1000));
            let a = parse(&jwt).unwrap();
            let ks = keys(s.jwk("k1"));
            assert_eq!(a.verify_signature(&ks), Ok(()), "{}", s.alg());
            assert_eq!(
                a.check_claims(cid, &["https://as.example", aud], 1000),
                Ok(())
            );
            // Wrong key: invalid; unknown kid: refetch hint.
            let other = match &s {
                Signer::Ec(_) => Signer::es256(),
                Signer::Rsa(_, alg) => Signer::rsa(alg),
            };
            assert!(matches!(
                a.verify_signature(&keys(other.jwk("k1"))),
                Err(SigError::Invalid(_))
            ));
            assert_eq!(
                a.verify_signature(&keys(s.jwk("k2"))),
                Err(SigError::UnknownKey)
            );
            // No kid in the header: every fitting key is tried.
            let a2 = parse(&s.sign(None, &claims(cid, aud, 1000))).unwrap();
            let mut two = keys(other.jwk("x"));
            two.extend(keys(s.jwk("y")));
            assert_eq!(a2.verify_signature(&two), Ok(()));
            // Tampered payload.
            let mut parts: Vec<&str> = jwt.split('.').collect();
            let forged = B64.encode(claims("https://evil.example/c", aud, 1000).to_string());
            parts[1] = &forged;
            let f = parse(&parts.join(".")).unwrap();
            assert!(matches!(f.verify_signature(&ks), Err(SigError::Invalid(_))));
        }
    }

    #[test]
    fn rejects_alg_none_hs256_and_mismatched_keys() {
        let rsa = Signer::rsa("RS256");
        let ks = keys(rsa.jwk("k1"));
        for alg in ["none", "HS256", "RS512"] {
            let h = B64.encode(json!({"alg":alg,"kid":"k1"}).to_string());
            let p = B64.encode(claims("c", "a", 1).to_string());
            let a = parse(&format!("{h}.{p}.")).unwrap();
            assert!(
                matches!(a.verify_signature(&ks), Err(SigError::Invalid(_))),
                "{alg}"
            );
        }
        // An RS256 token against an EC key, or a key restricted to PS256.
        let jwt = rsa.sign(Some("k1"), &claims("c", "a", 1));
        let a = parse(&jwt).unwrap();
        assert_eq!(
            a.verify_signature(&keys(Signer::es256().jwk("k1"))),
            Err(SigError::UnknownKey)
        );
        let mut pinned = rsa.jwk("k1");
        pinned["alg"] = json!("PS256");
        assert_eq!(a.verify_signature(&keys(pinned)), Err(SigError::UnknownKey));
        let mut enc = rsa.jwk("k1");
        enc["use"] = json!("enc");
        assert_eq!(a.verify_signature(&keys(enc)), Err(SigError::UnknownKey));
        assert!(parse("a.b").is_err() && parse("a.b.c.d").is_err());
        assert!(parse(&"a".repeat(MAX_JWT_LEN + 1)).is_err());
    }

    #[test]
    fn claim_checks() {
        let cid = "https://client.example/cimd.json";
        let iss = "https://as.example";
        let tok = "https://as.example/oauth/token";
        let now = 10_000;
        let check = |v: serde_json::Value| {
            let s = Signer::es256();
            parse(&s.sign(None, &v))
                .unwrap()
                .check_claims(cid, &[iss, tok], now)
        };
        assert_eq!(check(claims(cid, tok, now)), Ok(()));
        assert_eq!(check(claims(cid, iss, now)), Ok(()));
        assert_eq!(
            check(claims(cid, "https://AS.example/", now)),
            Ok(()),
            "canonical aud"
        );
        let mut v = claims(cid, tok, now);
        v["aud"] = json!(["https://other.example", tok]);
        assert_eq!(check(v), Ok(()), "aud array");
        assert!(check(claims(cid, "https://other.example", now)).is_err());
        let mut v = claims(cid, tok, now);
        v["iss"] = json!("https://evil.example/c");
        assert!(check(v).is_err());
        let mut v = claims(cid, tok, now);
        v["sub"] = json!("someone");
        assert!(check(v).is_err());
        let mut v = claims(cid, tok, now);
        v["exp"] = json!(now - 61);
        assert_eq!(check(v), Err("client assertion expired"));
        let mut v = claims(cid, tok, now);
        v["exp"] = json!(now - 30);
        assert_eq!(check(v), Ok(()), "within skew");
        let mut v = claims(cid, tok, now);
        v["exp"] = json!(now + MAX_LIFETIME + 120);
        assert_eq!(check(v), Err("client assertion lives too long"));
        let mut v = claims(cid, tok, now);
        v.as_object_mut().unwrap().remove("exp");
        assert_eq!(check(v), Err("client assertion without exp"));
        let mut v = claims(cid, tok, now);
        v["nbf"] = json!(now + 600);
        assert_eq!(check(v), Err("client assertion not valid yet"));
        let mut v = claims(cid, tok, now);
        v["jti"] = json!("");
        assert!(check(v).is_err());
        assert_eq!(
            unverified_subject(&Signer::es256().sign(None, &claims(cid, tok, now))).as_deref(),
            Some(cid)
        );
    }
}
