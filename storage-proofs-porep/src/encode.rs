use blstrs::Scalar as Fr;
use filecoin_hashers::Domain;

pub fn encode<T: Domain>(key: T, value: T) -> T {
    let mut result: Fr = value.into();
    let key: Fr = key.into();

    result += key;
    result.into()
}

pub fn decode<T: Domain>(key: T, value: T) -> T {
    let mut result: Fr = value.into();
    let key: Fr = key.into();

    result -= key;
    result.into()
}
