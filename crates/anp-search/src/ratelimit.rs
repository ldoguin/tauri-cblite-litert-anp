//! A token bucket per client, for the methods that make this agent fetch from the network.

use std::collections::HashMap;
use std::sync::Mutex;

/// Keys remembered at most. Buckets that have refilled to full carry no information and are dropped first; if the table is
/// still full, new clients wait.
const MAX_KEYS: usize = 10_000;

pub struct Limiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<String, (f64, f64)>>,
}

impl Limiter {
    /// `burst` requests at once, then one every `seconds_per_request`.
    pub fn new(burst: u32, seconds_per_request: f64) -> Limiter {
        Limiter { capacity: burst as f64, refill_per_sec: 1.0 / seconds_per_request.max(0.001), buckets: Mutex::new(HashMap::new()) }
    }

    /// `Ok` if `key` may go ahead at `now` (seconds, any steady clock), else the whole seconds until it may.
    pub fn allow(&self, key: &str, now: f64) -> Result<(), u64> {
        let mut b = self.buckets.lock().unwrap();
        if b.len() >= MAX_KEYS && !b.contains_key(key) {
            let (cap, rate) = (self.capacity, self.refill_per_sec);
            b.retain(|_, (tokens, at)| *tokens + (now - *at).max(0.0) * rate < cap);
            if b.len() >= MAX_KEYS {
                return Err((1.0 / rate).ceil() as u64);
            }
        }
        let (tokens, at) = b.entry(key.to_string()).or_insert((self.capacity, now));
        *tokens = (*tokens + (now - *at).max(0.0) * self.refill_per_sec).min(self.capacity);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - *tokens) / self.refill_per_sec).ceil() as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_allowed_then_the_client_waits_and_is_let_in_again() {
        let l = Limiter::new(3, 10.0);
        for _ in 0..3 {
            assert!(l.allow("a", 100.0).is_ok());
        }
        assert_eq!(l.allow("a", 100.0), Err(10));
        assert_eq!(l.allow("a", 104.0), Err(6), "it says how long is left");
        assert!(l.allow("a", 110.0).is_ok(), "one request after ten seconds");
        assert!(l.allow("a", 110.0).is_err());
    }

    #[test]
    fn clients_do_not_share_a_bucket_and_idle_ones_are_forgotten_when_full() {
        let l = Limiter::new(1, 60.0);
        assert!(l.allow("a", 0.0).is_ok());
        assert!(l.allow("b", 0.0).is_ok());
        assert!(l.allow("a", 1.0).is_err());
        for i in 0..MAX_KEYS {
            let _ = l.allow(&format!("k{i}"), 2.0);
        }
        // the table is full of clients that have just used their one request: a newcomer waits
        assert!(l.allow("newcomer", 3.0).is_err());
        // a minute on they have all refilled, so there is room again
        assert!(l.allow("newcomer", 70.0).is_ok());
    }
}