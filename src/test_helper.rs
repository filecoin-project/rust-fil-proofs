#[macro_export]
macro_rules! table_tests {
    ($property_test_func:ident {
        $( $(#[$attr:meta])* $test_name:ident( $( $param:expr ),* ); )+
    }) => {
        $(
            $(#[$attr])*
                #[test]
            fn $test_name() {
                $property_test_func($( $param ),* )
            }
        )+
    }
}
