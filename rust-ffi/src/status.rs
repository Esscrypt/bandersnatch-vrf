use std::cell::RefCell;

pub const SUCCESS: i32 = 0;
pub const MALFORMED: i32 = 1;
pub const INVALID_ARGUMENT: i32 = 2;
pub const UNKNOWN_HANDLE: i32 = 3;
pub const NATIVE_FAILURE: i32 = 4;
pub const PANIC: i32 = 5;
pub const ABI_MISMATCH: i32 = 6;
pub const RESOURCE_EXHAUSTION: i32 = 7;

const _: [i32; 8] = [
    SUCCESS,
    MALFORMED,
    INVALID_ARGUMENT,
    UNKNOWN_HANDLE,
    NATIVE_FAILURE,
    PANIC,
    ABI_MISMATCH,
    RESOURCE_EXHAUSTION,
];

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

pub fn set_last_error(message: impl Into<String>) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(message.into()));
}

pub fn take_last_error() -> Option<String> {
    LAST_ERROR.with(|slot| slot.borrow_mut().take())
}

pub fn fail(code: i32, message: impl Into<String>) -> i32 {
    set_last_error(message);
    code
}
