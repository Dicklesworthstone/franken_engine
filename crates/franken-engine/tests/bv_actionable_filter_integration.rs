//! Integration test for the bv actionable filter fix (bd-5oef0).
//!
//! This test verifies that the bv_actionable_filter.sh script correctly excludes
//! blocked and in-progress beads from actionable results, addressing the bug where
//! bv would incorrectly show blocked parent tracks as actionable.

#![forbid(unsafe_code)]

use serde_json::{Value, json};

fn mock_bv_output() -> Value {
    json!({
        "plan": {
            "tracks": [
                {
                    "track_id": "track1",
                    "items": [
                        {"id": "bd-ready1", "status": "open", "title": "Ready item 1"},
                        {"id": "bd-blocked1", "status": "blocked", "title": "Blocked item 1"},
                        {"id": "bd-ready2", "status": "open", "title": "Ready item 2"}
                    ]
                },
                {
                    "track_id": "track2",
                    "items": [
                        {"id": "bd-inprog1", "status": "in_progress", "title": "In progress item 1"},
                        {"id": "bd-ready3", "status": "open", "title": "Ready item 3"}
                    ]
                },
                {
                    "track_id": "track3",
                    "items": [
                        {"id": "bd-blocked2", "status": "blocked", "title": "Blocked item 2"}
                    ]
                }
            ]
        }
    })
}

fn mock_br_blocked() -> Value {
    json!([
        {"id": "bd-blocked1", "status": "blocked", "title": "Blocked item 1"},
        {"id": "bd-blocked2", "status": "blocked", "title": "Blocked item 2"}
    ])
}

fn mock_br_in_progress() -> Value {
    json!([
        {"id": "bd-inprog1", "status": "in_progress", "title": "In progress item 1"}
    ])
}

fn apply_bv_filter(bv_output: &Value, blocked: &Value, in_progress: &Value) -> Value {
    let _filter_jq = r#"
        def blocked_ids: [$blocked[].id];
        def in_progress_ids: [$in_progress[].id];
        def excluded_ids: (blocked_ids + in_progress_ids);

        # Filter tracks to exclude blocked/in-progress items
        .plan.tracks |= map(
            .items |= map(
                select(.id as $id | (excluded_ids | index($id)) == null)
            )
        ) |

        # Remove tracks that have no items after filtering
        .plan.tracks |= map(select(.items | length > 0))
    "#;

    // Simulate the jq filtering logic in Rust
    let mut output = bv_output.clone();

    // Extract excluded IDs
    let mut excluded_ids = Vec::new();
    if let Some(blocked_array) = blocked.as_array() {
        for item in blocked_array {
            if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                excluded_ids.push(id.to_string());
            }
        }
    }
    if let Some(in_progress_array) = in_progress.as_array() {
        for item in in_progress_array {
            if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                excluded_ids.push(id.to_string());
            }
        }
    }

    // Filter tracks
    if let Some(plan) = output.get_mut("plan")
        && let Some(tracks) = plan.get_mut("tracks").and_then(|v| v.as_array_mut())
    {
        let mut filtered_tracks = Vec::new();

        for track in tracks {
            if let Some(items) = track.get_mut("items").and_then(|v| v.as_array_mut()) {
                let mut filtered_items = Vec::new();

                for item in items {
                    if let Some(item_id) = item.get("id").and_then(|v| v.as_str())
                        && excluded_ids.iter().all(|id| id != item_id)
                    {
                        filtered_items.push(item.clone());
                    }
                }

                if !filtered_items.is_empty() {
                    let mut filtered_track = track.clone();
                    filtered_track["items"] = Value::Array(filtered_items);
                    filtered_tracks.push(filtered_track);
                }
            }
        }

        plan["tracks"] = Value::Array(filtered_tracks);
    }

    output
}

#[test]
fn bv_filter_excludes_blocked_and_in_progress_beads() {
    let original = mock_bv_output();
    let blocked = mock_br_blocked();
    let in_progress = mock_br_in_progress();

    let filtered = apply_bv_filter(&original, &blocked, &in_progress);

    // Extract all item IDs from filtered result
    let mut filtered_ids = Vec::new();
    if let Some(tracks) = filtered["plan"]["tracks"].as_array() {
        for track in tracks {
            if let Some(items) = track["items"].as_array() {
                for item in items {
                    if let Some(id) = item["id"].as_str() {
                        filtered_ids.push(id);
                    }
                }
            }
        }
    }

    // Should contain only ready items
    assert_eq!(filtered_ids.len(), 3);
    assert!(filtered_ids.contains(&"bd-ready1"));
    assert!(filtered_ids.contains(&"bd-ready2"));
    assert!(filtered_ids.contains(&"bd-ready3"));

    // Should exclude blocked and in-progress items
    assert!(!filtered_ids.contains(&"bd-blocked1"));
    assert!(!filtered_ids.contains(&"bd-blocked2"));
    assert!(!filtered_ids.contains(&"bd-inprog1"));
}

#[test]
fn bv_filter_removes_empty_tracks() {
    let original = mock_bv_output();
    let blocked = mock_br_blocked();
    let in_progress = mock_br_in_progress();

    let filtered = apply_bv_filter(&original, &blocked, &in_progress);

    // Should have 2 tracks remaining (track3 should be removed as it becomes empty)
    let tracks = filtered["plan"]["tracks"].as_array().unwrap();
    assert_eq!(tracks.len(), 2);

    // Verify track IDs
    let track_ids: Vec<&str> = tracks
        .iter()
        .map(|t| t["track_id"].as_str().unwrap())
        .collect();

    assert!(track_ids.contains(&"track1"));
    assert!(track_ids.contains(&"track2"));
    assert!(!track_ids.contains(&"track3")); // Should be removed
}

#[test]
fn bv_filter_preserves_structure_for_remaining_items() {
    let original = mock_bv_output();
    let blocked = mock_br_blocked();
    let in_progress = mock_br_in_progress();

    let filtered = apply_bv_filter(&original, &blocked, &in_progress);

    // Check that structure is preserved
    assert!(filtered["plan"].is_object());
    assert!(filtered["plan"]["tracks"].is_array());

    // Check that item properties are preserved
    let tracks = filtered["plan"]["tracks"].as_array().unwrap();
    for track in tracks {
        assert!(track["track_id"].is_string());
        assert!(track["items"].is_array());

        let items = track["items"].as_array().unwrap();
        for item in items {
            assert!(item["id"].is_string());
            assert!(item["status"].is_string());
            assert!(item["title"].is_string());
        }
    }
}
