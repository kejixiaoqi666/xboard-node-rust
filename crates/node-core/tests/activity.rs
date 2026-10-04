use node_core::ActivitySnapshot;
use std::collections::BTreeMap;

#[test]
fn audit_separates_sessions_users_and_shared_source_ips() {
    let snapshot = ActivitySnapshot {
        alive: BTreeMap::from([
            (7, vec!["192.0.2.7".into()]),
            (9, vec!["192.0.2.7".into(), "2001:db8::9".into()]),
        ]),
        online: BTreeMap::from([(7, 2), (9, 2)]),
        sessions: 4,
    };
    let audit = snapshot.audit().expect("valid activity sample");
    assert_eq!(audit.tracked_users, 2);
    assert_eq!(audit.online_users, 2);
    assert_eq!(audit.unique_source_ips, 2);
    assert_eq!(audit.user_source_ip_pairs, 3);
    assert_eq!(audit.reused_source_ip_pairs, 1);
    assert_eq!(audit.sessions, 4);
    assert_eq!(audit.users[&7].sessions, 2);
    assert_eq!(audit.users[&7].source_ips, 1);
    assert_eq!(audit.users[&9].sessions, 2);
    assert_eq!(audit.users[&9].source_ips, 2);
}

#[test]
fn audit_rejects_duplicate_ip_membership_inside_one_user() {
    let snapshot = ActivitySnapshot {
        alive: BTreeMap::from([(7, vec!["192.0.2.7".into(), "192.0.2.7".into()])]),
        online: BTreeMap::from([(7, 2)]),
        sessions: 2,
    };
    assert!(!snapshot.validate());
    assert!(snapshot.audit().is_none());
}

#[test]
fn audit_canonicalizes_ipv4_mapped_source_ip_reuse() {
    let snapshot = ActivitySnapshot {
        alive: BTreeMap::from([
            (7, vec!["192.0.2.7".into()]),
            (9, vec!["::ffff:192.0.2.7".into()]),
        ]),
        online: BTreeMap::from([(7, 1), (9, 1)]),
        sessions: 2,
    };
    let audit = snapshot.audit().expect("valid activity sample");
    assert_eq!(audit.unique_source_ips, 1);
    assert_eq!(audit.user_source_ip_pairs, 2);
    assert_eq!(audit.reused_source_ip_pairs, 1);
}

#[test]
fn audit_counts_zero_session_users_as_tracked_but_not_online() {
    let snapshot = ActivitySnapshot {
        alive: BTreeMap::from([(7, Vec::new()), (9, vec!["192.0.2.9".into()])]),
        online: BTreeMap::from([(7, 0), (9, 1)]),
        sessions: 1,
    };
    let audit = snapshot.audit().expect("valid activity sample");
    assert_eq!(audit.tracked_users, 2);
    assert_eq!(audit.online_users, 1);
    assert_eq!(audit.unique_source_ips, 1);
}
