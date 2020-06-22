/// Checks that the two passed values are equal. If they are not equal it prints a debug and returns `false`.
macro_rules! check_eq {
    ($left:expr , $right:expr,) => ({
        check_eq!($left, $right)
    });
    ($left:expr , $right:expr) => ({
        match (&($left), &($right)) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    log::debug!("check failed: `(left == right)`\
                          \n\
                          \n{}\
                          \n",
                           pretty_assertions::Comparison::new(left_val, right_val));
                    return false;
                }
            }
        }
    });
    ($left:expr , $right:expr, $($arg:tt)*) => ({
        match (&($left), &($right)) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    log::debug!("check failed: `(left == right)`: {}\
                          \n\
                          \n{}\
                          \n",
                           format_args!($($arg)*),
                           pretty_assertions::Comparison::new(left_val, right_val));
                    return false;
                }
            }
        }
    });
}

/// Checks that the passed in value is true. If they are not equal it prints a debug and returns `false`.
macro_rules! check {
    ($val:expr) => {
        if !$val {
            log::debug!("expected {:?} to be true", dbg!($val));
            return false;
        }
    };
    ($val:expr, $($arg:tt)*) => ({
        if !$val {
            log::debug!("expected {:?} to be true`\
                         \n\
                         \n{}\
                         \n",
                        dbg!($val),
                        format_args!($($arg)*));
            return false;
        }
    });
}

macro_rules! prefetch {
    ($val:expr) => {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        unsafe {
            #[cfg(target_arch = "x86")]
            use std::arch::x86::*;
            #[cfg(target_arch = "x86_64")]
            use std::arch::x86_64::*;

            _mm_prefetch($val, _MM_HINT_T0);
        }
    };
}
