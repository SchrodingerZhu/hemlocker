#![feature(strict_provenance_atomic_ptr)]
#![feature(error_in_core)]
#![no_std]
extern crate alloc;

use alloc::sync::{Arc, Weak};
use core::error::Error as ErrorTrait;
use core::marker::PhantomPinned;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use parking_lot_core::SpinWait;

// Both [`HolderWord`] and [`LockWord`] need to be pinned. Otherwise, rust is free to move them around.
// However, we want their address to be stable.

#[repr(transparent)]
#[derive(Default)]
pub struct HolderWord {
    grant: AtomicPtr<LockWord>,
    _pinned: PhantomPinned,
}

#[repr(transparent)]
#[derive(Default)]
pub struct LockWord {
    tail: AtomicPtr<HolderWord>,
    _pinned: PhantomPinned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    UnlockInProgress,
    DeadPredecessor,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnlockInProgress => write!(f, "unlock in progress"),
            Error::DeadPredecessor => write!(f, "dead predecessor"),
        }
    }
}

impl ErrorTrait for Error {}

// To begin with, Arc/Rc in rust is designed as a pointer to a heap-allocated block
//                 -----------------------
//                 |     ArcBox<T>       |
//                 -----------------------
//                 | strong: AtomicUsize |
//                 -----------------------
//                 |  weak: AtomicUsize  |
//                 -----------------------
//                 |       data: T       |
//                 -----------------------

// When both strong and weak count are zero, the ArcBox<T> is dropped. Otherwise, if the strong count is zero,
// then only the data field is dropped in place. So it is safe to use weak to detect the live/dead
// status of the ArcBox<T>.
impl LockWord {
    pub const fn new() -> Self {
        LockWord {
            tail: AtomicPtr::new(ptr::null_mut()),
            _pinned: PhantomPinned,
        }
    }
    pub fn is_locked(&self) -> bool {
        !self.tail.load(Ordering::Acquire).is_null()
    }
    pub fn try_lock_with(&self, holder: &Arc<HolderWord>) -> Result<(), Error> {
        // First, we check if target holder is currently awaiting for its successor to notice the unlock.
        // If so, such progress can not be interrupted.
        if !holder.grant.load(Ordering::Relaxed).is_null() {
            return Err(Error::UnlockInProgress);
        }
        // Get a weak pointer to the holder. Since we need to store it to the lock word, we need to
        // leak the raw pointer to the holder. This memory is eventually not leaked since the weak pointer
        // will be recovered during either unlocking, waiting or lock destruction.
        let weak_holder = Arc::downgrade(holder).into_raw() as *mut _;

        // Check if the lock has been acquired by other thread. If so, we need to wait for the predecessor.
        let pred = self.tail.swap(weak_holder, Ordering::AcqRel);
        if !pred.is_null() {
            // Upgrade the weak pointer to a strong one as we need to access the predecessor.
            let pred = unsafe { Weak::from_raw(pred) };
            let mut waiter = SpinWait::new();
            loop {
                match pred.upgrade() {
                    Some(pred) => {
                        let addr = self as *const _ as *mut _;
                        // Check if predecessor want to grant/release the lock to us.
                        // [`compare_exchange_weak`] is good enough as we are going to spin.
                        if pred
                            .grant
                            .compare_exchange_weak(
                                addr,
                                ptr::null_mut(),
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_err()
                        {
                            // We failed to acquire the lock. We need to wait for the predecessor.
                            // During the waiting, the predecessor may die. So we drop the strong
                            // pointer. Next time we weak up, we will try to retain it
                            // again from the weak pointer. Then we can notice the death of the
                            // predecessor.
                            drop(pred);
                            waiter.spin();
                        } else {
                            // We have acquired the lock.
                            break;
                        }
                    }
                    // The predecessor is dead. We cannot acquire the lock anymore.
                    None => return Err(Error::DeadPredecessor),
                }
            }
        }
        Ok(())
    }
    pub fn try_unlock_with(&self, holder: &HolderWord) -> Result<(), Error> {
        // First, we check if target holder is currently awaiting for its successor to notice the unlock.
        // If so, such progress can not be interrupted.
        if !holder.grant.load(Ordering::Relaxed).is_null() {
            return Err(Error::UnlockInProgress);
        }
        // Do aggressive handover. This is safe as we are holding a reference to holder, so the holder is
        // guaranteed by Rust type system to be alive during the process.
        holder
            .grant
            .store(self as *const _ as *mut _, Ordering::Release);
        let holder_addr = holder as *const _ as *mut _;

        // Since we only do single round of [`compare_exchange`], we have to use the strong version, which rule out
        // suprious failures.
        match self.tail.compare_exchange(
            holder_addr,
            ptr::null_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(addr) => {
                // There is no thread waiting for the lock. We decrease the weak count of the holder on our own.
                // Notice that the holder is still alive even though we have decreased the weak count.
                unsafe {
                    Weak::from_raw(addr);
                }
                holder.grant.store(ptr::null_mut(), Ordering::Release);
            }
            Err(_) => {
                // There is a thread waiting for the lock. We need to wait for the successor to notice the unlock.
                // Just do a spin wait.
                let mut waiter = SpinWait::new();
                while !holder.grant.fetch_ptr_add(0, Ordering::AcqRel).is_null() {
                    waiter.spin();
                }
            }
        }
        Ok(())
    }
}

impl Drop for LockWord {
    fn drop(&mut self) {
        // When a lock is dropped, we need to recover the weak pointer to the holder.
        // This will decrease the weak count of the holder, since the weak pointer is dropped immediately.
        let addr = self.tail.load(Ordering::Relaxed);
        if !addr.is_null() {
            unsafe {
                Weak::from_raw(addr);
            }
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{Error, HolderWord, LockWord};
    use alloc::sync::Arc;
    #[test]
    fn trivial_lock_unlock() {
        let lock = LockWord::default();
        let holder = Arc::new(HolderWord::default());
        lock.try_lock_with(&holder).unwrap();
        lock.try_unlock_with(&holder).unwrap();
    }
    #[test]
    fn trivial_dead_pred() {
        let lock = LockWord::default();
        {
            let holder = Arc::new(HolderWord::default());
            lock.try_lock_with(&holder).unwrap();
        }
        let holder = Arc::new(HolderWord::default());
        assert_eq!(lock.try_lock_with(&holder), Err(Error::DeadPredecessor));
    }
    #[test]
    fn single_thread_multiple_lock() {
        let lock0 = LockWord::default();
        let lock1 = LockWord::default();
        let holder = Arc::new(HolderWord::default());
        lock0.try_lock_with(&holder).unwrap();
        lock1.try_lock_with(&holder).unwrap();
        lock0.try_unlock_with(&holder).unwrap();
        lock1.try_unlock_with(&holder).unwrap();
    }

    #[test]
    fn single_lock_multiple_thread() {
        let lock = LockWord::default();
        let counter = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..20 {
                let lock = &lock;
                let counter = &counter;
                scope.spawn(move || {
                    let holder = Arc::new(HolderWord::default());
                    for _ in 0..20 {
                        lock.try_lock_with(&holder).unwrap();
                        let value = counter.load(Ordering::Relaxed);
                        counter.store(value + 1, Ordering::Relaxed);
                        lock.try_unlock_with(&holder).unwrap();
                    }
                });
            }
        });
        assert_eq!(counter.load(Ordering::Relaxed), 400);
    }

    #[test]
    fn rotation_locking() {
        let lock = [
            LockWord::default(),
            LockWord::default(),
            LockWord::default(),
            LockWord::default(),
            LockWord::default(),
            LockWord::default(),
            LockWord::default(),
            LockWord::default(),
            LockWord::default(),
            LockWord::default(),
        ];
        let values = [
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        ];
        std::thread::scope(|scope| {
            for i in 0..20 {
                let lock = &lock;
                let values = &values;
                scope.spawn(move || {
                    let holder = Arc::new(HolderWord::default());
                    for j in 0..30 {
                        let target = ((i + j) % 10) as usize;
                        lock[target].try_lock_with(&holder).unwrap();
                        let value = values[target].load(Ordering::Relaxed);
                        values[target].store(value + 1, Ordering::Relaxed);
                        lock[target].try_unlock_with(&holder).unwrap();
                    }
                });
            }
        });
        for i in values.iter() {
            assert_eq!(i.load(Ordering::Relaxed), 60);
        }
    }
}
