use lock_api::{GuardNoSend, RawMutex};
use raw_locker::{Error::*, HolderWord, LockWord};
use std::sync::Arc;
std::thread_local! {
    static TLS_HOLDER_WORD : Arc<HolderWord> = Default::default();
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
        TLS_HOLDER_WORD.with(|holder| match self.0.try_lock_with(holder) {
            Ok(_) => {}
            Err(DeadPredecessor) => {
                panic!("dead predecessor detected")
            }
            Err(UnlockInProgress) => {
                panic!("locking logic error detected")
            }
        })
    }

    fn try_lock(&self) -> bool {
        TLS_HOLDER_WORD.with(|holder| self.0.try_lock_with(holder).is_ok())
    }

    unsafe fn unlock(&self) {
        TLS_HOLDER_WORD.with(|holder| {
            if self.0.try_unlock_with(holder).is_err() {
                panic!("unlocking logic error detected")
            }
        })
    }

    #[inline]
    fn is_locked(&self) -> bool {
        self.0.is_locked()
    }
}

pub type HemLock<T> = lock_api::Mutex<RawLocker, T>;
pub type HemLockGuard<'a, T> = lock_api::MutexGuard<'a, RawLocker, T>;
