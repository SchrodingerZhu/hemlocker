#![feature(strict_provenance_atomic_ptr)]
#![no_std]
extern crate alloc;
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
    pub unsafe fn lock(&self, holder: &HolderWord) {
        let holder_ptr = holder as *const _ as *mut _;
        let pred = self.tail.swap(holder_ptr, Ordering::AcqRel);
        if !pred.is_null() {
            let mut waiter = SpinWait::new();
            let addr = self as *const _ as *mut _;

            // Check if predecessor want to grant/release the lock to us.
            // [`compare_exchange_weak`] is good enough as we are going to spin.
            while (*pred)
                .grant
                .compare_exchange_weak(addr, ptr::null_mut(), Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                waiter.spin();
            }
        }
    }
    pub unsafe fn unlock(&self, holder: &HolderWord) {
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
            Ok(_) => {
                // There is no thread waiting for the lock.
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
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use core::sync::atomic::{AtomicUsize, Ordering};

    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn trivial_lock_unlock() {
        let lock = LockWord::default();
        let holder = Arc::new(HolderWord::default());
        unsafe {
            lock.lock(&holder);
            lock.unlock(&holder);
        }
    }

    #[test]
    fn single_thread_multiple_lock() {
        let lock0 = LockWord::default();
        let lock1 = LockWord::default();
        let holder = Arc::new(HolderWord::default());
        unsafe {
            lock0.lock(&holder);
            lock1.lock(&holder);
            lock0.unlock(&holder);
            lock1.unlock(&holder);
        }
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
                        unsafe {
                            lock.lock(&holder);
                            let value = counter.load(Ordering::Relaxed);
                            counter.store(value + 1, Ordering::Relaxed);
                            lock.unlock(&holder);
                        }
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
                        unsafe {
                            lock[target].lock(&holder);
                            let value = values[target].load(Ordering::Relaxed);
                            values[target].store(value + 1, Ordering::Relaxed);
                            lock[target].unlock(&holder);
                        }
                    }
                });
            }
        });
        for i in values.iter() {
            assert_eq!(i.load(Ordering::Relaxed), 60);
        }
    }
}
