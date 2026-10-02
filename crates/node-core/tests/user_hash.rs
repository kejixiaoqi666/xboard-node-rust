use node_core::{UserSpec, user_hash};

#[test]
fn go_service_user_hash_vector_matches_regardless_of_order() {
    // Produced by Go internal/service.computeUserHash on commit 25ca043.
    let users = vec![
        UserSpec::new(9, "user-nine").with_limits(50, 2),
        UserSpec::new(3, "user-three"),
    ];
    let expected = "f07d7ef5ed249daa39762158415065cb2a0d59889fbca257abaad2fc43e76ac1";
    assert_eq!(user_hash(&users), expected);
    assert_eq!(user_hash(&[users[1].clone(), users[0].clone()]), expected);
}

#[test]
fn speed_or_device_limit_changes_hash() {
    let a = UserSpec::new(3, "u");
    assert_ne!(
        user_hash(std::slice::from_ref(&a)),
        user_hash(&[a.clone().with_limits(1, 0)])
    );
    assert_ne!(
        user_hash(std::slice::from_ref(&a)),
        user_hash(&[a.with_limits(0, 1)])
    );
}
