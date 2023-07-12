use lock_api::{GuardNoSend, RawMutex};
use raw_locker::{Error::*, HolderWord, LockWord};
use std::sync::Arc;
std::thread_local! {
    static ROBURST_TLS_HOLDER_WORD : Arc<HolderWord> = Default::default();
    static TLS_HOLDER_WORD : HolderWord = Default::default();
}

#[repr(transparent)]
pub struct RobustRawLocker(LockWord);

// 2. Implement RawMutex for this type
unsafe impl RawMutex for RobustRawLocker {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: RobustRawLocker = RobustRawLocker(LockWord::new());

    // A spinlock guard can be sent to another thread and unlocked there
    type GuardMarker = GuardNoSend;

    fn lock(&self) {
        ROBURST_TLS_HOLDER_WORD.with(|holder| match self.0.try_lock_with(holder) {
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
        ROBURST_TLS_HOLDER_WORD.with(|holder| self.0.try_lock_with(holder).is_ok())
    }

    unsafe fn unlock(&self) {
        ROBURST_TLS_HOLDER_WORD.with(|holder| {
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

#[repr(transparent)]
pub struct RawLocker(LockWord);

// 2. Implement RawMutex for this type
unsafe impl RawMutex for RawLocker {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: RawLocker = RawLocker(LockWord::new());

    // A spinlock guard can be sent to another thread and unlocked there
    type GuardMarker = GuardNoSend;

    fn lock(&self) {
        TLS_HOLDER_WORD.with(|holder| unsafe { self.0.untracked_lock_with(holder) });
    }

    fn try_lock(&self) -> bool {
        TLS_HOLDER_WORD.with(|holder| unsafe { self.0.untracked_lock_with(holder) });
        true
    }

    unsafe fn unlock(&self) {
        TLS_HOLDER_WORD.with(|holder| unsafe { self.0.untracked_unlock_with(holder) });
    }

    #[inline]
    fn is_locked(&self) -> bool {
        self.0.is_locked()
    }
}

pub type RobustHemLock<T> = lock_api::Mutex<RobustRawLocker, T>;
pub type RobustHemLockGuard<'a, T> = lock_api::MutexGuard<'a, RobustRawLocker, T>;
pub type HemLock<T> = lock_api::Mutex<RawLocker, T>;
pub type HemLockGuard<'a, T> = lock_api::MutexGuard<'a, RawLocker, T>;

#[cfg(test)]
mod test {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn robust_hemlock() {
        use crate::RobustHemLock;
        let lock = RobustHemLock::new(());
        let flag = Arc::new(AtomicBool::new(false));

        std::thread::scope(|x| {
            x.spawn(|| {
                std::mem::forget(lock.lock());
                flag.store(true, Ordering::SeqCst);
            });

            x.spawn(|| {
                while !flag.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                lock.try_lock();
            });
        });
    }
}
