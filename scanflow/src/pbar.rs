#[cfg(feature = "progress_bar")]
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[cfg(feature = "progress_bar")]
use std::thread::{spawn, JoinHandle};

/// Describes a progress bar.
///
/// This structure is active only when `progress_bar` feature is enabled.
pub struct PBar {
    #[cfg(feature = "progress_bar")]
    handle: Option<JoinHandle<()>>,
    #[cfg(feature = "progress_bar")]
    cnt: Arc<AtomicU64>,
}

#[cfg(feature = "progress_bar")]
impl PBar {
    pub fn new(max_length: u64, as_bytes: bool) -> Self {
        let cnt = Arc::new(AtomicU64::new(0));

        let cnt2 = cnt.clone();

        Self {
            handle: Some(spawn(move || {
                let mut pbar = pbr::ProgressBar::new(max_length);
                let cnt = cnt2;

                if as_bytes {
                    pbar.set_units(pbr::Units::Bytes);
                }

                let timeout = std::time::Duration::from_millis(30);

                loop {
                    std::thread::sleep(timeout);
                    let loaded = cnt.load(Ordering::Acquire);

                    if loaded == !0 {
                        pbar.finish();
                        break;
                    }

                    pbar.set(loaded);
                }
            })),
            cnt,
        }
    }

    pub fn add(&self, add: u64) {
        self.cnt.fetch_add(add, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.add(1);
    }

    pub fn set(&self, value: u64) {
        self.cnt.store(value, Ordering::Relaxed);
    }

    pub fn finish(self) {}
}

#[cfg(feature = "progress_bar")]
impl Drop for PBar {
    fn drop(&mut self) {
        self.cnt.store(!0, Ordering::Release);
        self.handle.take().unwrap().join().unwrap();
    }
}

#[cfg(not(feature = "progress_bar"))]
impl PBar {
    pub fn new(_max_length: u64, _as_bytes: bool) -> Self {
        Self {}
    }

    pub fn add(&self, _add: u64) {}

    pub fn inc(&self) {}

    pub fn set(&self, _value: u64) {}

    pub fn finish(self) {}
}
