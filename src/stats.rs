use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use crate::utils::human_bytes;

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        #[derive(Default)]
        pub struct Stats {
            pub connections_active: AtomicI64,
            $(pub $name: AtomicU64,)*
        }

        impl Stats {
            pub fn reset(&self) {
                self.connections_active.store(0, Ordering::Relaxed);
                $(self.$name.store(0, Ordering::Relaxed);)*
            }
        }
    };
}

counters!(
    connections_total,
    connections_ws,
    connections_h2,
    h2_tcp_connections,
    h2_requests,
    h2_errors,
    connections_tcp_fallback,
    connections_cfproxy,
    connections_fronting,
    connections_bad,
    connections_masked,
    ws_errors,
    bytes_up,
    bytes_down,
    pool_hits,
    pool_misses,
    cf_pool_hits,
    cf_pool_misses,
);

pub fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub fn add(counter: &AtomicU64, value: u64) {
    counter.fetch_add(value, Ordering::Relaxed);
}

pub fn get(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

impl Stats {
    pub fn summary(&self) -> String {
        let pool_hits = get(&self.pool_hits);
        let pool_total = pool_hits + get(&self.pool_misses);
        let pool = if pool_total > 0 {
            format!("{pool_hits}/{pool_total}")
        } else {
            "n/a".to_string()
        };
        let cf_hits = get(&self.cf_pool_hits);
        let cf_total = cf_hits + get(&self.cf_pool_misses);
        let cf_pool = if cf_total > 0 {
            format!("{cf_hits}/{cf_total}")
        } else {
            "n/a".to_string()
        };
        format!(
            "total={} active={} ws={} h2={} h2_tcp={} h2_req={} h2_err={} tcp_fb={} cf={} \
             front={} bad={} masked={} err={} pool={} cf_pool={} up={} down={}",
            get(&self.connections_total),
            self.connections_active.load(Ordering::Relaxed),
            get(&self.connections_ws),
            get(&self.connections_h2),
            get(&self.h2_tcp_connections),
            get(&self.h2_requests),
            get(&self.h2_errors),
            get(&self.connections_tcp_fallback),
            get(&self.connections_cfproxy),
            get(&self.connections_fronting),
            get(&self.connections_bad),
            get(&self.connections_masked),
            get(&self.ws_errors),
            pool,
            cf_pool,
            human_bytes(get(&self.bytes_up)),
            human_bytes(get(&self.bytes_down)),
        )
    }
}

pub static STATS: std::sync::LazyLock<Stats> = std::sync::LazyLock::new(Stats::default);

pub fn stats() -> &'static Stats {
    &STATS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_reports_pool_ratio_and_totals() {
        let stats = Stats::default();
        assert!(stats.summary().contains("pool=n/a"));
        inc(&stats.pool_hits);
        inc(&stats.pool_hits);
        inc(&stats.pool_misses);
        add(&stats.bytes_up, 2048);
        let text = stats.summary();
        assert!(text.contains("pool=2/3"));
        assert!(text.contains("up=2.0KB"));
        stats.reset();
        assert!(stats.summary().contains("pool=n/a"));
    }
}
