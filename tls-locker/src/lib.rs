#![feature(cell_update, thread_id_value)]
use std::cell::Cell;

use lock_api::{GuardNoSend, RawMutex};
use raw_locker::{HolderWord, LockWord};
std::thread_local! {
    static TLS_HOLDER_WORD : HolderWord = Default::default();
    static HOUSE_KEEPER: HouseKeeper = Default::default();
}

#[derive(Default)]
struct HouseKeeper {
    held_locks: Cell<usize>,
}

#[repr(transparent)]
pub struct RawLocker(LockWord);

// 2. Implement RawMutex for this type
unsafe impl RawMutex for RawLocker {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: RawLocker = RawLocker(LockWord::new());

    // A spinlock guard can be sent to another thread and unlocked there
    type GuardMarker = GuardNoSend;

    fn lock(&self) {
        TLS_HOLDER_WORD.with(|holder| unsafe { self.0.lock(holder) });
        HOUSE_KEEPER.with(|counter| counter.held_locks.update(|x| x + 1));
    }

    fn try_lock(&self) -> bool {
        let locked = TLS_HOLDER_WORD.with(|holder| unsafe { self.0.try_lock(holder) });
        if locked {
            HOUSE_KEEPER.with(|counter| counter.held_locks.update(|x| x + 1));
        }
        locked
    }

    unsafe fn unlock(&self) {
        TLS_HOLDER_WORD.with(|holder| unsafe { self.0.unlock(holder) });
        HOUSE_KEEPER.with(|counter| counter.held_locks.update(|x| x - 1));
    }

    #[inline]
    fn is_locked(&self) -> bool {
        self.0.is_locked()
    }
}

pub type HemLock<T> = lock_api::Mutex<RawLocker, T>;
pub type HemLockGuard<'a, T> = lock_api::MutexGuard<'a, RawLocker, T>;

impl Drop for HouseKeeper {
    fn drop(&mut self) {
        let count = self.held_locks.get();
        if count != 0 {
            panic!(
                "thread {} failed to release {} lock(s) before exiting",
                std::thread::current().id().as_u64(),
                count
            )
        }
    }
}

#[cfg(test)]
mod test {
    use crate::HemLock;

    #[test]
    fn simple_addition() {
        use rayon::prelude::*;
        let data = HemLock::new(0);
        (1..=1000).into_par_iter()
            .for_each(|x| *data.lock() += x);
        assert_eq!(data.lock().clone(), 500500);
    }
}