//! How much a tunnel carried recently, for telling a busy tunnel from one that only exchanges
//! keepalives and the odd DNS lookup.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// A sliding window over a running byte total.
pub struct Activity {
    window: Duration,
    /// (when, total so far), oldest first. The first sample is the baseline: the newest one
    /// that is at least a window old, or the oldest there is.
    samples: VecDeque<(Instant, u64)>,
}

impl Activity {
    pub fn new(window: Duration) -> Activity {
        Activity {
            window,
            samples: VecDeque::new(),
        }
    }

    /// Records the running total at `now` and returns how many bytes the tunnel carried within
    /// the window ending now.
    pub fn record(&mut self, now: Instant, total: u64) -> u64 {
        self.samples.push_back((now, total));
        while self.samples.len() >= 2
            && now.saturating_duration_since(self.samples[1].0) >= self.window
        {
            self.samples.pop_front();
        }
        total.saturating_sub(self.samples[0].1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn counts_the_last_window() {
        let start = Instant::now();
        let mut activity = Activity::new(MINUTE);
        // Nothing yet.
        assert_eq!(activity.record(start, 0), 0);
        // 10 bytes a second for a minute and a half.
        let mut recent = 0;
        for s in 1..=90 {
            recent = activity.record(start + Duration::from_secs(s), s * 10);
        }
        assert_eq!(recent, 600, "only the last minute counts");
        // Traffic stops: the window drains over the next minute.
        assert_eq!(activity.record(start + Duration::from_secs(120), 900), 300);
        assert_eq!(activity.record(start + Duration::from_secs(151), 900), 0);
    }

    #[test]
    fn baseline_is_the_newest_old_sample() {
        let start = Instant::now();
        let mut activity = Activity::new(MINUTE);
        activity.record(start, 0);
        activity.record(start + Duration::from_secs(30), 100);
        activity.record(start + Duration::from_secs(59), 100);
        // 61 seconds in: the sample from the start is just outside the window, the one from 30
        // seconds in is inside, so the start is the baseline.
        assert_eq!(activity.record(start + Duration::from_secs(61), 150), 150);
        // 91 seconds in: both earlier samples are a window old; the 30-second one is the newest.
        assert_eq!(activity.record(start + Duration::from_secs(91), 150), 50);
    }
}
