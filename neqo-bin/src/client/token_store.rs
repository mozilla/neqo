// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Write as _},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use nss::{ResumptionToken, TokenKind};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use super::{Error, Res};
use crate::now;

#[derive(Deserialize, Serialize)]
struct StoredToken {
    /// Seconds since `UNIX_EPOCH`.
    expiration_time: u64,
    max_early_data_size: u32,
    #[serde(with = "hex")]
    token: Vec<u8>,
}

impl StoredToken {
    fn new(token: &ResumptionToken, clock: &Clock) -> Self {
        Self {
            expiration_time: clock.unix_secs(token.expiration_time()),
            max_early_data_size: token.max_early_data_size(),
            token: token.as_ref().to_vec(),
        }
    }

    fn into_resumption_token(self, clock: &Clock) -> ResumptionToken {
        ResumptionToken::new_with_kind_and_early_data(
            TokenKind::Plaintext(self.token),
            clock.instant(self.expiration_time),
            self.max_early_data_size,
        )
    }
}

/// A wall clock time and the `Instant` it corresponds to.
struct Clock {
    wall: SystemTime,
    instant: Instant,
}

impl Clock {
    fn new() -> Self {
        Self {
            wall: SystemTime::now(),
            instant: now(),
        }
    }

    fn unix_secs(&self, at: Instant) -> u64 {
        let wall = if at >= self.instant {
            self.wall.checked_add(at - self.instant)
        } else {
            self.wall.checked_sub(self.instant - at)
        };
        wall.and_then(|w| w.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs())
    }

    fn instant(&self, unix_secs: u64) -> Instant {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(unix_secs))
            .and_then(|at| match at.duration_since(self.wall) {
                Ok(d) => self.instant.checked_add(d),
                Err(e) => self.instant.checked_sub(e.duration()),
            })
            .unwrap_or(self.instant)
    }
}

fn in_file(path: &Path) -> impl FnOnce(Error) -> Error {
    move |e| Error::TokenStore(path.to_owned(), Box::new(e))
}

/// Resumption tokens per origin (`host:port`).
#[derive(Default)]
pub struct TokenStore {
    tokens: BTreeMap<String, Vec<ResumptionToken>>,
}

impl TokenStore {
    pub fn load(path: &Path) -> Res<Self> {
        Self::read(path).map_err(in_file(path))
    }

    fn read(path: &Path) -> Res<Self> {
        let json = match fs::read_to_string(path) {
            Ok(json) => json,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                info!("No token store at {}", path.display());
                return Ok(Self::default());
            }
            Err(e) => return Err(e.into()),
        };
        let stored: BTreeMap<String, Vec<StoredToken>> = serde_json::from_str(&json)?;
        let clock = Clock::new();
        let tokens = stored
            .into_iter()
            .map(|(origin, list)| {
                let list = list
                    .into_iter()
                    .map(|t| t.into_resumption_token(&clock))
                    .filter(|t| t.expiration_time() > clock.instant)
                    .collect();
                (origin, list)
            })
            .collect();
        Ok(Self { tokens })
    }

    pub fn save(&self, path: &Path) -> Res<()> {
        self.save_at(path, &Clock::new()).map_err(in_file(path))
    }

    fn save_at(&self, path: &Path, clock: &Clock) -> Res<()> {
        let stored: BTreeMap<_, Vec<_>> = self
            .tokens
            .iter()
            .filter_map(|(origin, list)| {
                let list: Vec<_> = list
                    .iter()
                    .filter(|t| {
                        let plaintext = t.is_plaintext();
                        if !plaintext {
                            error!("Not saving encrypted resumption token for {origin}");
                        }
                        plaintext && t.expiration_time() > clock.instant
                    })
                    .map(|t| StoredToken::new(t, clock))
                    .collect();
                (!list.is_empty()).then_some((origin, list))
            })
            .collect();
        let tmp = path.with_added_extension("tmp");
        let mut file = File::create(&tmp)?;
        file.write_all(&serde_json::to_vec(&stored)?)?;
        file.sync_all()?;
        Ok(fs::rename(tmp, path)?)
    }

    /// Removes and returns the unexpired token for `origin` that expires last.
    pub fn take(&mut self, origin: &str) -> Option<ResumptionToken> {
        let tokens = self.tokens.get_mut(origin)?;
        let now = now();
        tokens.retain(|t| t.expiration_time() > now);
        let (last, _) = tokens
            .iter()
            .enumerate()
            .max_by_key(|(_, t)| t.expiration_time())?;
        Some(tokens.swap_remove(last))
    }

    pub fn extend<I: IntoIterator<Item = ResumptionToken>>(&mut self, origin: &str, tokens: I) {
        self.tokens
            .entry(origin.to_owned())
            .or_default()
            .extend(tokens);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use nss::{ResumptionToken, TokenKind};

    use super::{Clock, Error, TokenStore};
    use crate::{now, temp_dir::TempDir};

    const ORIGIN: &str = "a:443";
    const LIFETIME: Duration = Duration::from_secs(3600);

    fn token(kind: TokenKind, expiration: Instant) -> ResumptionToken {
        ResumptionToken::new_with_kind_and_early_data(kind, expiration, 7)
    }

    fn valid(bytes: &[u8]) -> ResumptionToken {
        token(TokenKind::Plaintext(bytes.to_vec()), now() + LIFETIME)
    }

    fn path(dir: &TempDir) -> PathBuf {
        dir.path().join("tokens.json")
    }

    fn save_load(store: &TokenStore, dir: &TempDir) -> TokenStore {
        let path = path(dir);
        store.save(&path).unwrap();
        TokenStore::load(&path).unwrap()
    }

    #[test]
    fn empty_round_trip() {
        let dir = TempDir::new();
        let path = path(&dir);
        TokenStore::default().save(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{}");
        assert!(TokenStore::load(&path).unwrap().take(ORIGIN).is_none());
    }

    #[test]
    fn saved_json() {
        let dir = TempDir::new();
        let path = path(&dir);
        let clock = Clock::new();
        let expiration = clock.instant + LIFETIME;
        let mut store = TokenStore::default();
        store.extend(
            ORIGIN,
            [token(TokenKind::Plaintext(vec![1, 2, 3]), expiration)],
        );
        store.save_at(&path, &clock).unwrap();
        let n = clock.unix_secs(expiration);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!(
                r#"{{"a:443":[{{"expiration_time":{n},"max_early_data_size":7,"token":"010203"}}]}}"#
            )
        );
    }

    #[test]
    fn load_missing_is_empty() {
        let dir = TempDir::new();
        let mut store = TokenStore::load(&dir.path().join("missing.json")).unwrap();
        assert!(store.take(ORIGIN).is_none());
    }

    #[test]
    fn load_bad_json_fails() {
        let dir = TempDir::new();
        let path = path(&dir);
        fs::write(&path, "not json").unwrap();
        assert_eq!(
            TokenStore::load(&path).err().unwrap().to_string(),
            format!(
                "token store {}: expected ident at line 1 column 2",
                path.display()
            )
        );
    }

    #[test]
    fn save_error_has_path() {
        let dir = TempDir::new();
        let path = dir.path().join("missing").join("tokens.json");
        let err = TokenStore::default().save(&path).unwrap_err();
        assert!(matches!(err, Error::TokenStore(p, e) if p == path && matches!(*e, Error::Io(_))));
    }

    #[test]
    fn newest_first_used_once() {
        let mut store = TokenStore::default();
        store.extend(
            ORIGIN,
            [
                token(TokenKind::Plaintext(vec![2]), now() + 2 * LIFETIME),
                valid(&[1]),
            ],
        );
        assert_eq!(store.take(ORIGIN).unwrap().as_ref(), [2]);
        assert_eq!(store.take(ORIGIN).unwrap().as_ref(), [1]);
        assert!(store.take(ORIGIN).is_none());
    }

    #[test]
    fn origins_separate() {
        let mut store = TokenStore::default();
        store.extend(ORIGIN, [valid(&[1])]);
        assert!(store.take("b:443").is_none());
    }

    #[test]
    fn expired_dropped() {
        let mut store = TokenStore::default();
        store.extend(ORIGIN, [token(TokenKind::Plaintext(vec![1]), now())]);
        assert!(save_load(&store, &TempDir::new()).take(ORIGIN).is_none());
    }

    #[test]
    fn load_expired_dropped() {
        let dir = TempDir::new();
        let path = path(&dir);
        fs::write(
            &path,
            r#"{"a:443":[{"expiration_time":1,"max_early_data_size":7,"token":"01"}]}"#,
        )
        .unwrap();
        let mut store = TokenStore::load(&path).unwrap();
        assert!(store.tokens[ORIGIN].is_empty());
        assert!(store.take(ORIGIN).is_none());
    }

    #[test]
    fn expired_not_taken() {
        let mut store = TokenStore::default();
        store.extend(
            ORIGIN,
            [valid(&[1]), token(TokenKind::Plaintext(vec![2]), now())],
        );
        assert_eq!(store.take(ORIGIN).unwrap().as_ref(), [1]);
        assert!(store.take(ORIGIN).is_none());
    }

    #[test]
    fn encrypted_skipped() {
        let mut store = TokenStore::default();
        store.extend(
            ORIGIN,
            [token(TokenKind::Encrypted(vec![1]), now() + LIFETIME)],
        );
        assert!(save_load(&store, &TempDir::new()).take(ORIGIN).is_none());
    }

    #[test]
    fn unused_loaded_token_resaved() {
        let dir = TempDir::new();
        let mut store = TokenStore::default();
        store.extend(ORIGIN, [valid(&[1, 2, 3])]);
        let mut store = save_load(&save_load(&store, &dir), &dir);
        let t = store.take(ORIGIN).unwrap();
        assert_eq!(t.as_ref(), [1, 2, 3]);
        assert!(t.is_plaintext());
        assert_eq!(t.max_early_data_size(), 7);
        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files, ["tokens.json"]);
    }

    #[test]
    fn used_token_not_saved() {
        let dir = TempDir::new();
        let path = path(&dir);
        let mut store = TokenStore::default();
        store.extend(ORIGIN, [valid(&[1])]);
        let mut store = save_load(&store, &dir);
        assert!(store.take(ORIGIN).is_some());
        store.save(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{}");
    }
}
