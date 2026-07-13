use std::time::Instant;

#[derive(Debug)]
pub(crate) struct MonotonicClock {
    #[cfg(debug_assertions)]
    source: DebugClockSource,
}

#[cfg(debug_assertions)]
#[derive(Debug)]
enum DebugClockSource {
    System,
    Controlled {
        origin: Instant,
        path: std::path::PathBuf,
        last_elapsed: std::time::Duration,
    },
}

impl Default for MonotonicClock {
    fn default() -> Self {
        #[cfg(debug_assertions)]
        {
            let source = std::env::var_os("HERDR_TEST_MONOTONIC_CLOCK_PATH")
                .map(std::path::PathBuf::from)
                .map_or(DebugClockSource::System, |path| {
                    DebugClockSource::Controlled {
                        origin: Instant::now(),
                        path,
                        last_elapsed: std::time::Duration::ZERO,
                    }
                });
            Self { source }
        }

        #[cfg(not(debug_assertions))]
        {
            Self {}
        }
    }
}

impl MonotonicClock {
    pub(crate) fn now(&mut self) -> Instant {
        #[cfg(debug_assertions)]
        {
            match &mut self.source {
                DebugClockSource::System => Instant::now(),
                DebugClockSource::Controlled {
                    origin,
                    path,
                    last_elapsed,
                } => {
                    let elapsed = std::fs::read_to_string(path)
                        .ok()
                        .and_then(|value| value.trim().parse::<u64>().ok())
                        .map(std::time::Duration::from_nanos)
                        .map(|elapsed| elapsed.max(*last_elapsed))
                        .unwrap_or(*last_elapsed);
                    let Some(now) = origin.checked_add(elapsed) else {
                        return origin.checked_add(*last_elapsed).unwrap_or(*origin);
                    };
                    *last_elapsed = elapsed;
                    now
                }
            }
        }

        #[cfg(not(debug_assertions))]
        {
            Instant::now()
        }
    }
}
