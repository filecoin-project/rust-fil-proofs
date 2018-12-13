use num_bigint::{BigInt, BigUint};

pub trait StaticAccumulator {
    /// Setup generates a group of unknown order and initializes the group
    /// with a generator of that group.
    fn setup(lambda: usize) -> Self;

    /// Update the accumulator.
    fn add(&mut self, x: &BigUint);

    /// Create a membership proof.
    /// Returns `None`, iff `x` is not a member.
    fn mem_wit_create(&self, x: &BigUint) -> BigUint;

    /// Verify a membership proof.
    fn ver_mem(&self, w: &BigUint, x: &BigUint) -> bool;
}

pub trait DynamicAccumulator: StaticAccumulator {
    /// Delete a value from the accumulator.
    fn del(&mut self, x: &BigUint) -> Option<()>;
}

pub trait UniversalAccumulator: DynamicAccumulator {
    /// Create a non-membership proof.
    /// Returns `None`, iff `x` is a member.
    fn non_mem_wit_create(&self, x: &BigUint) -> (BigUint, BigInt);

    /// Verify a non-membership proof.
    fn ver_non_mem(&self, w: &(BigUint, BigInt), x: &BigUint) -> bool;
}

pub trait BatchedAccumulator: StaticAccumulator {
    /// Batch add.
    /// Given a list of new elements, adds them.
    fn batch_add(&mut self, xs: &[BigUint]) -> BigUint;

    /// Batch delete.
    /// Given a list of witnesses and members, deletes all of them.
    fn batch_del(&mut self, pairs: &[(BigUint, BigUint)]) -> Option<BigUint>;

    /// Delete with member witness.
    /// Deletes a single element, given the element and a wittness for it.
    /// Returns `None` if the element was not actual a member.
    fn del_w_mem(&mut self, w: &BigUint, x: &BigUint) -> Option<()>;

    /// Create membership witnesses for all elements in `s`.
    /// Needs to be passed in, as we don't hold onto the whole set in the accumulator currently.
    fn create_all_mem_wit(&self, s: &[BigUint]) -> Vec<BigUint>;

    /// Verify Batch Add.
    /// Given the proof `w` from [batch_add] and the list of members `xs`,
    /// and the previous state of the accumulator `a_t` this verifies if the `add` was done correctly.
    ///
    /// Note: This is not explicitly defined in the paper, but here for convenience.
    fn ver_batch_add(&self, w: &BigUint, a_t: &BigUint, xs: &[BigUint]) -> bool;

    /// Verify Batch Del
    /// Given the proof `w` from [batch_del] and the list of members `xs`,
    /// and the previous state of the accumulator `a_t` this verifies if the `del` was done correctly.
    ///
    /// Note: This is not explicitly defined in the paper, but here for convenience.
    fn ver_batch_del(&self, w: &BigUint, a_t: &BigUint, xs: &[BigUint]) -> bool;
}
