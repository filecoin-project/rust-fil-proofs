use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use bitvec::{BitVec, LittleEndian};
use fil_sapling_crypto::jubjub::{edwards, read_exp_table_range, JubjubParams, PrimeOrder};
use fil_sapling_crypto::pedersen_hash::{pedersen_hash_with_exp_table, Personalization};
use paired::bls12_381::{Bls12, Fr};

use crate::crypto::pedersen::JJ_PARAMS;

const N_SEGMENTS_PER_PARTITION: usize = 5;
const N_BITS_PER_SEGMENT: usize = 189;

type WorkerId = usize;
type PreimageId = usize;
type ExpTable = Vec<Vec<Vec<edwards::Point<Bls12, PrimeOrder>>>>;

#[derive(Debug)]
struct ExpTableRange {
    first: usize,
    stop: usize,
}

impl ExpTableRange {
    fn new(first: usize, stop: usize) -> Self {
        ExpTableRange { first, stop }
    }

    fn stop(&self) -> usize {
        self.stop
    }

    fn move_forward_n_segments(&mut self, n_segments: usize) {
        self.first = self.stop;
        self.stop = self.first + n_segments;
    }
}

pub enum Message {
    Init(PreimageId),
    Update(PreimageId, [u8; 32]),
    Done,
}

#[derive(Clone, PartialEq, Eq)]
struct State {
    curr_hash: edwards::CompressedPoint<Bls12, PrimeOrder>,
    unhashed_bits: BitVec<LittleEndian, u8>,
}

impl Default for State {
    fn default() -> State {
        State {
            curr_hash: edwards::Point::<Bls12, PrimeOrder>::zero().compress(),
            unhashed_bits: BitVec::new(),
        }
    }
}

impl State {
    fn new() -> State {
        State::default()
    }

    fn update(&mut self, data: &[u8], exp_table: &[Vec<Vec<edwards::Point<Bls12, PrimeOrder>>>]) {
        let input_bits = BitVec::<LittleEndian, u8>::from(data);

        let n_input_bits = input_bits.len();
        let n_stored_bits = self.unhashed_bits.len();
        let n_bits_total = n_input_bits + n_stored_bits;

        if n_bits_total < N_BITS_PER_SEGMENT {
            self.unhashed_bits.extend(input_bits);
            return;
        }

        let n_bits_to_store = n_bits_total % N_BITS_PER_SEGMENT;
        let n_bits_to_hash = n_bits_total - n_bits_to_store;

        let bits_to_hash = self
            .unhashed_bits
            .iter()
            .chain(input_bits.iter())
            .take(n_bits_to_hash);

        let digest = pedersen_hash_with_exp_table(
            Personalization::None,
            bits_to_hash,
            exp_table,
            &JJ_PARAMS,
        );

        self.curr_hash = self
            .curr_hash
            .decompress(&JJ_PARAMS)
            .add(&digest, &JJ_PARAMS)
            .compress();

        let n_input_bits_hashed = n_input_bits - n_bits_to_store;
        self.unhashed_bits = input_bits.iter().skip(n_input_bits_hashed).collect();
    }

    fn finalize(&mut self, exp_table: &[Vec<Vec<edwards::Point<Bls12, PrimeOrder>>>]) -> Fr {
        let n_unhashed_bits = self.unhashed_bits.len();

        if n_unhashed_bits == 0 {
            return self.curr_hash.decompress(&JJ_PARAMS).into_xy().0;
        }

        let bits_to_hash = self.unhashed_bits.iter().take(n_unhashed_bits);

        let segment_digest = pedersen_hash_with_exp_table(
            Personalization::None,
            bits_to_hash,
            exp_table,
            &JJ_PARAMS,
        );

        let curr_hash = self
            .curr_hash
            .decompress(&JJ_PARAMS)
            .add(&segment_digest, &JJ_PARAMS);

        let digest = curr_hash.into_xy().0;
        self.curr_hash = curr_hash.compress();
        digest
    }

    fn n_unhashed_bits(&mut self) -> usize {
        self.unhashed_bits.len()
    }
}

pub struct ParallelPedersen {
    senders: HashMap<WorkerId, Sender<Message>>,
    exp_table: Arc<RwLock<ExpTable>>,
    exp_table_range: Arc<RwLock<ExpTableRange>>,
    n_threads: Arc<RwLock<usize>>,
    n_threads_waiting: Arc<RwLock<usize>>,
}

impl ParallelPedersen {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let n_segments_in_memory = JJ_PARAMS.pedersen_hash_exp_table().len();
        let exp_table_range = Arc::new(RwLock::new(ExpTableRange::new(0, n_segments_in_memory)));

        ParallelPedersen {
            senders: HashMap::new(),
            exp_table: Arc::new(RwLock::new(vec![])),
            exp_table_range,
            n_threads: Arc::new(RwLock::new(0)),
            n_threads_waiting: Arc::new(RwLock::new(0)),
        }
    }

    pub fn new_worker(&mut self) -> Worker {
        let worker_id = self.senders.len();
        let (msg_sender, msg_receiver) = channel::<Message>();

        let worker = Worker {
            msg_receiver,
            states: HashMap::new(),
            has_been_updated: HashMap::new(),
            next_segment: 0,
            exp_table: self.exp_table.clone(),
            exp_table_range: self.exp_table_range.clone(),
            n_threads: self.n_threads.clone(),
            n_threads_waiting: self.n_threads_waiting.clone(),
            thread_is_waiting: false,
        };

        self.senders.insert(worker_id, msg_sender);
        *self.n_threads.write().unwrap() += 1;
        worker
    }

    pub fn send_msg_to_worker(&mut self, worker_id: WorkerId, msg: Message) {
        self.senders
            .get(&worker_id)
            .expect("worker does not exist")
            .send(msg)
            .expect("worker thread panicked");
    }
}

pub struct Worker {
    msg_receiver: Receiver<Message>,
    states: HashMap<PreimageId, State>,
    has_been_updated: HashMap<PreimageId, bool>,
    next_segment: usize,
    exp_table: Arc<RwLock<ExpTable>>,
    exp_table_range: Arc<RwLock<ExpTableRange>>,
    n_threads: Arc<RwLock<usize>>,
    n_threads_waiting: Arc<RwLock<usize>>,
    thread_is_waiting: bool,
}

impl Worker {
    pub fn new_preimage(&mut self, preimage_id: PreimageId) {
        let preimage_id_already_exists = self.states.contains_key(&preimage_id);
        assert!(!preimage_id_already_exists);
        self.states.insert(preimage_id, State::new());
        self.has_been_updated.insert(preimage_id, false);
    }

    fn advance_exp_table(&mut self) {
        let mut exp_table = self.exp_table.write().unwrap();
        let mut exp_table_range = self.exp_table_range.write().unwrap();
        let first_segment_in_next_partition = exp_table_range.stop();
        let exp_table_path = JJ_PARAMS.exp_table_path().as_ref().unwrap();

        *exp_table = read_exp_table_range(
            first_segment_in_next_partition,
            N_SEGMENTS_PER_PARTITION,
            exp_table_path,
        )
        .expect("failed to read exp-table file");

        let n_segments_read = exp_table.len();
        assert!(n_segments_read != 0, "ran out of segments in exp-table");
        exp_table_range.move_forward_n_segments(n_segments_read);
        *self.n_threads_waiting.write().unwrap() = 0;
        self.thread_is_waiting = false;
    }

    pub fn update_preimage(&mut self, preimage_id: PreimageId, data: &[u8]) {
        let has_already_been_updated = *self
            .has_been_updated
            .get(&preimage_id)
            .expect("worker does not have a state for the given id");

        if has_already_been_updated {
            panic!("cannot update a state twice in one layer");
        }

        // Wait for the next exp-table partition to load.
        if self.thread_is_waiting {
            loop {
                let exp_table_range = self.exp_table_range.read().unwrap();
                let n_segments_remaining_in_exp_table = exp_table_range.stop() - self.next_segment;
                drop(exp_table_range);
                if n_segments_remaining_in_exp_table > 0 {
                    self.thread_is_waiting = false;
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }

        let state = self.states.get_mut(&preimage_id).unwrap();
        let exp_table = self.exp_table.read().unwrap();
        let exp_table_range = self.exp_table_range.read().unwrap();
        let n_segments_remaining_in_exp_table = exp_table_range.stop() - self.next_segment;

        let (n_segments_to_hash, ready_to_advance_exp_table) = {
            let n_unhashed_bits = state.n_unhashed_bits();
            let n_update_bits = data.len() * 8;
            let n_bits_total = n_unhashed_bits + n_update_bits;
            let n_segments_of_data = n_bits_total / N_BITS_PER_SEGMENT;

            if n_segments_of_data < n_segments_remaining_in_exp_table {
                (n_segments_of_data, false)
            } else {
                (n_segments_remaining_in_exp_table, true)
            }
        };

        let use_static_params = self.next_segment < JJ_PARAMS.pedersen_hash_exp_table().len();

        let exp_table_slice = if use_static_params {
            &JJ_PARAMS.pedersen_hash_exp_table()[self.next_segment..]
        } else {
            let offset = exp_table.len() - n_segments_remaining_in_exp_table;
            &exp_table[offset..]
        };

        state.update(data, exp_table_slice);
        *self.has_been_updated.get_mut(&preimage_id).unwrap() = true;

        let all_states_have_been_updated = self
            .has_been_updated
            .values()
            .all(|has_been_updated| *has_been_updated);

        if all_states_have_been_updated {
            self.next_segment += n_segments_to_hash;

            self.has_been_updated
                .values_mut()
                .for_each(|has_been_updated| *has_been_updated = false);

            if ready_to_advance_exp_table {
                self.thread_is_waiting = true;
                let mut n_threads_waiting = self.n_threads_waiting.write().unwrap();
                *n_threads_waiting += 1;
                if *n_threads_waiting == *self.n_threads.read().unwrap() {
                    drop(exp_table);
                    drop(exp_table_range);
                    drop(n_threads_waiting);
                    self.advance_exp_table();
                }
            }
        }
    }

    pub fn finalize_preimage(&mut self, preimage_id: PreimageId) -> Fr {
        let state = self
            .states
            .get_mut(&preimage_id)
            .expect("state does not exist in worker");

        // This could be the case if we are the first call to finalize in a thread, but the thread
        // previous to is responsible for updating the exp-table.
        if self.thread_is_waiting {
            loop {
                let exp_table_range = self.exp_table_range.read().unwrap();
                let n_segments_remaining_in_exp_table = exp_table_range.stop() - self.next_segment;
                drop(exp_table_range);
                if n_segments_remaining_in_exp_table > 0 {
                    self.thread_is_waiting = false;
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }

        // If there are no preimage bits remaining, we can just return the state's current hash
        // value. This will also be the case if we have already called `finalize()` on this
        // preimage's state.
        let n_unhashed_bits = state.n_unhashed_bits();
        if n_unhashed_bits == 0 {
            return state.finalize(&[]);
        }

        // Sanity check that there is less than or equal to one segment's worth of unhashed
        // preimage data.
        let n_segments_to_hash =
            (n_unhashed_bits as f32 / N_BITS_PER_SEGMENT as f32).ceil() as usize;

        assert_eq!(
            n_segments_to_hash, 1,
            "called finalize with more than one segment's worth of outstanding data"
        );

        let exp_table = self.exp_table.read().unwrap();
        let exp_table_range = self.exp_table_range.read().unwrap();
        let use_static_params = self.next_segment < JJ_PARAMS.pedersen_hash_exp_table().len();

        let exp_table_slice = if use_static_params {
            &JJ_PARAMS.pedersen_hash_exp_table()[self.next_segment..]
        } else {
            let n_segments_remaining_in_exp_table = exp_table_range.stop() - self.next_segment;

            // Sanity check that we have at least one segment remaining in the exp-table.
            assert!(
                n_segments_remaining_in_exp_table >= 1,
                "ran out of segments in exp-table"
            );

            let offset = exp_table.len() - n_segments_remaining_in_exp_table;
            &exp_table[offset..]
        };

        // Hash the last segment (or partial segment) of the preimage.
        let digest = state.finalize(exp_table_slice);
        *self.has_been_updated.get_mut(&preimage_id).unwrap() = true;
        digest
    }

    pub fn finalize_all(&mut self) -> Vec<Fr> {
        let mut preimage_ids: Vec<PreimageId> = self.states.keys().copied().collect();
        preimage_ids.sort_unstable();

        preimage_ids
            .into_iter()
            .map(|preimage_id| self.finalize_preimage(preimage_id))
            .collect()
    }

    pub fn listen_for_work(&mut self) -> Vec<Fr> {
        loop {
            match self.msg_receiver.recv().unwrap() {
                Message::Init(preimage_id) => self.new_preimage(preimage_id),
                Message::Update(preimage_id, bytes) => self.update_preimage(preimage_id, &bytes),
                Message::Done => return self.finalize_all(),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::thread::JoinHandle;

    use fil_sapling_crypto::pedersen_hash::pedersen_hash;
    use rand::{thread_rng, Rng};

    fn sapling_pedersen_hash(preimage: &[u8]) -> Fr {
        let preimage_len = preimage.len();
        let bits = BitVec::<bitvec::LittleEndian, u8>::from(preimage);
        pedersen_hash::<Bls12, _>(
            Personalization::None,
            bits.iter().take(8 * preimage_len),
            &JJ_PARAMS,
        )
        .into_xy()
        .0
    }

    #[test]
    fn test_parallel_pedersen() {
        let n_threads = 20;
        let n_preimages_per_thread = 20;
        let preimage_len = 96;

        // Create the preimages for each worker.
        let mut rng = thread_rng();
        let mut preimages: Vec<Vec<Vec<u8>>> = Vec::with_capacity(n_threads);

        for _ in 0..n_threads {
            let thread_preimages: Vec<Vec<u8>> = (0..n_preimages_per_thread)
                .map(|_| (0..preimage_len).map(|_| rng.gen()).collect())
                .collect();

            preimages.push(thread_preimages);
        }

        // Create a hash "coordinator" and one hash worker per thread.
        let mut hash_coordinator = ParallelPedersen::new();

        let handles: Vec<JoinHandle<Vec<Fr>>> = (0..n_threads)
            .map(|_| {
                let mut hasher = hash_coordinator.new_worker();
                thread::spawn(move || hasher.listen_for_work())
            })
            .collect();

        // Tell each of the worker threads to create `State`s for their preimages.
        for worker_id in 0..n_threads {
            for preimage_id in 0..n_preimages_per_thread {
                hash_coordinator.send_msg_to_worker(worker_id, Message::Init(preimage_id));
            }
        }

        // Update and finalize each preimage.
        let n_updates = preimage_len / 32;

        for worker_id in 0..n_threads {
            for update_index in 0..n_updates {
                let start = update_index * 32;
                let stop = start + 32;
                for preimage_id in 0..n_preimages_per_thread {
                    let update_bytes = &preimages[worker_id][preimage_id][start..stop];
                    let mut bytes_to_send = [0u8; 32];
                    bytes_to_send.copy_from_slice(update_bytes);
                    hash_coordinator
                        .send_msg_to_worker(worker_id, Message::Update(preimage_id, bytes_to_send));
                }
            }
            hash_coordinator.send_msg_to_worker(worker_id, Message::Done);
        }

        // Check that each worker's digest matches the digest produced by sapling.
        for (worker_id, handle) in handles.into_iter().enumerate() {
            let digests = handle.join().unwrap();
            for (preimage_id, digest) in digests.into_iter().enumerate() {
                let preimage = &preimages[worker_id][preimage_id];
                let expected_digest = sapling_pedersen_hash(&preimage);
                assert_eq!(digest, expected_digest);
            }
        }
    }
}
