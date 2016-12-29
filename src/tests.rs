use List;

#[test]
fn test_fetch() {
    let list = List::fetch().unwrap();
    panic!(format!("{:?}", list));
}
