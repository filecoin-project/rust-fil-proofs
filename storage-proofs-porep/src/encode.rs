use ff::PrimeField;
use filecoin_hashers::Domain;

pub fn encode<T: Domain>(key: T, value: T) -> T {
    let value: T::Field = value.into();
    let mut result: T::Field = key.into();

    encode_fr(&mut result, value);
    result.into()
}

pub fn encode_fr<F: PrimeField>(key: &mut F, value: F) {
    *key += value;
}

pub fn decode<T: Domain>(key: T, value: T) -> T {
    let mut result: T::Field = value.into();
    let key: T::Field = key.into();

    result -= key;
    result.into()
}
