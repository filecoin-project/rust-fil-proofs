use blstrs::Scalar as Fr;
use filecoin_hashers::Domain;

pub fn encode<T: Domain>(key: T, value: T) -> T {
    let value: Fr = value.into();
    let mut result: Fr = key.into();

    encode_fr(&mut result, value);
    result.into()
}

pub fn encode_fr(key: &mut Fr, value: Fr) {
    *key += value;
}

pub fn decode<T: Domain>(key: T, value: T) -> T {
    let mut result: Fr = value.into();
    let key: Fr = key.into();

    result -= key;
    result.into()
}
