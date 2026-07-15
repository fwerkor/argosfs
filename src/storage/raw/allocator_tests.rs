use super::*;

#[test]
fn allocator_reuses_freed_extents_and_reports_enospc() {
    let mut state = init_allocator(4096, 16 * 4096, 4096);
    let first = allocate(&mut state, "disk-0000", 1000, 1).unwrap();
    let second = allocate(&mut state, "disk-0000", 1000, 1).unwrap();
    assert_ne!(first.offset, second.offset);
    free(&mut state, &first).unwrap();
    let reused = allocate(&mut state, "disk-0000", 1000, 2).unwrap();
    assert_eq!(reused.offset, first.offset);
    assert!(matches!(
        allocate(&mut state, "disk-0000", 128 * 4096, 1).unwrap_err(),
        ArgosError::DiskFull { .. }
    ));
}

#[test]
fn allocator_detects_overlaps() {
    let state = init_allocator(4096, 16 * 4096, 4096);
    let a = PhysicalExtent {
        disk_id: "disk-0000".to_string(),
        offset: 4096,
        length: 8192,
        generation: 1,
        flags: 0,
    };
    let b = PhysicalExtent {
        offset: 8192,
        ..a.clone()
    };
    assert!(matches!(
        validate_allocations(&state, vec![a, b]).unwrap_err(),
        ArgosError::CorruptedMetadata(_)
    ));
}

#[test]
fn allocator_detects_free_list_overlapping_allocated_extent() {
    let mut state = init_allocator(4096, 16 * 4096, 4096);
    let allocated = allocate(&mut state, "disk-0000", 4096, 1).unwrap();
    state.free_extents.push(RawFreeExtent {
        offset: allocated.offset,
        length: allocated.length,
    });
    assert!(matches!(
        validate_allocations(&state, vec![allocated]).unwrap_err(),
        ArgosError::CorruptedMetadata(_)
    ));
}
