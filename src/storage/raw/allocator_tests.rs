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

#[test]
fn allocator_free_and_validation_reject_all_out_of_region_cases() {
    let mut state = init_allocator(4096, 4 * 4096, 4096);
    let before = PhysicalExtent {
        disk_id: "disk-0000".to_string(),
        offset: 0,
        length: 4096,
        generation: 1,
        flags: 0,
    };
    let after = PhysicalExtent {
        offset: state.data_end,
        ..before.clone()
    };
    assert!(free(&mut state, &before).is_err());
    assert!(free(&mut state, &after).is_err());
    let zero = PhysicalExtent {
        offset: state.data_start,
        length: 0,
        ..before.clone()
    };
    free(&mut state, &zero).unwrap();
    assert!(state.free_extents.is_empty());

    assert!(validate_allocations(&state, vec![before.clone()]).is_err());
    assert!(validate_allocations(&state, vec![after.clone()]).is_err());

    state.free_extents = vec![RawFreeExtent {
        offset: 0,
        length: 4096,
    }];
    assert!(validate_allocations(&state, Vec::new()).is_err());
    state.free_extents = vec![RawFreeExtent {
        offset: state.data_end,
        length: 4096,
    }];
    assert!(validate_allocations(&state, Vec::new()).is_err());
    state.free_extents = vec![
        RawFreeExtent {
            offset: 4096,
            length: 8192,
        },
        RawFreeExtent {
            offset: 8192,
            length: 4096,
        },
    ];
    assert!(validate_allocations(&state, Vec::new()).is_err());
}

#[test]
fn allocator_coalesces_adjacent_overlapping_and_partial_free_extents() {
    let mut state = init_allocator(4096, 8 * 4096, 4096);
    let full = allocate(&mut state, "disk", 3 * 4096, 1).unwrap();
    let middle = PhysicalExtent {
        offset: full.offset + 4096,
        length: 4096,
        ..full.clone()
    };
    let first = PhysicalExtent {
        length: 4096,
        ..full.clone()
    };
    let last = PhysicalExtent {
        offset: full.offset + 2 * 4096,
        length: 4096,
        ..full
    };
    free(&mut state, &middle).unwrap();
    free(&mut state, &first).unwrap();
    free(&mut state, &last).unwrap();
    assert_eq!(state.free_extents.len(), 1);
    assert_eq!(state.free_extents[0].offset, 4096);
    assert_eq!(state.free_extents[0].length, 3 * 4096);

    let partial = allocate(&mut state, "disk", 4096, 2).unwrap();
    assert_eq!(partial.offset, 4096);
    assert_eq!(state.free_extents[0].offset, 8192);
    assert_eq!(state.free_extents[0].length, 2 * 4096);
}
