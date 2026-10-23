//! The wiping allocator installed as a program's global allocator, as the env
//! engine installs it. Run under Miri, these check that wiping and resizing
//! blocks is defined behavior, including for bytes that were never written.

use std::mem::MaybeUninit;

#[global_allocator]
static ALLOCATOR: lpm_env_backup::WipingAllocator = lpm_env_backup::WipingAllocator;

#[test]
fn blocks_never_written_or_written_in_part_are_freed() {
    drop(Vec::<u8>::with_capacity(64));
    let mut part = Vec::with_capacity(4096);
    part.extend_from_slice(b"written in part");
    drop(part);
    drop(Box::<[MaybeUninit<u64>]>::new_uninit_slice(33));
}

#[test]
fn blocks_holding_padding_or_unset_enum_payloads_are_freed() {
    #[repr(C)]
    struct Padded {
        narrow: u8,
        wide: u64,
        short: u16,
    }
    let padded = Box::new(Padded {
        narrow: 1,
        wide: 2,
        short: 3,
    });
    assert_eq!(
        u64::from(padded.narrow) + padded.wide + u64::from(padded.short),
        6
    );
    drop(padded);
    let options = vec![Some(1u8), None, Some(3)];
    assert_eq!(options.iter().flatten().count(), 2);
    drop(options);
}

/// The engine hands out results this way: a vector shrunk to a boxed slice,
/// leaked, then rebuilt from its pointer, wiped and freed.
#[test]
fn a_vector_shrunk_to_a_boxed_slice_and_rebuilt_from_its_pointer_is_freed() {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&[7u8; 43]);
    let raw = Box::into_raw(bytes.into_boxed_slice());
    // SAFETY: `raw` is the unchanged boxed slice just leaked.
    let mut output = unsafe { Box::from_raw(raw) };
    output.fill(0);
    drop(output);
}

#[test]
fn blocks_grown_and_shrunk_keep_their_data() {
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(b"abc");
    bytes.reserve(4096);
    assert!(bytes.capacity() >= 4099);
    bytes.shrink_to_fit();
    assert_eq!(bytes.capacity(), 3);
    bytes.truncate(1);
    bytes.shrink_to_fit();
    assert_eq!(bytes, b"a");
    let mut wide: Vec<u64> = (0..1000).collect();
    wide.truncate(10);
    wide.shrink_to_fit();
    assert_eq!(wide, (0..10).collect::<Vec<_>>());
}
