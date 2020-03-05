use fake_simd::u32x4;

pub const STATE_LEN: usize = 8;
pub const BLOCK_LEN: usize = 16;

/// Constants necessary for SHA-256 family of digests.
pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Constants necessary for SHA-256 family of digests.
pub const K32X4: [u32x4; 16] = [
    u32x4(K32[3], K32[2], K32[1], K32[0]),
    u32x4(K32[7], K32[6], K32[5], K32[4]),
    u32x4(K32[11], K32[10], K32[9], K32[8]),
    u32x4(K32[15], K32[14], K32[13], K32[12]),
    u32x4(K32[19], K32[18], K32[17], K32[16]),
    u32x4(K32[23], K32[22], K32[21], K32[20]),
    u32x4(K32[27], K32[26], K32[25], K32[24]),
    u32x4(K32[31], K32[30], K32[29], K32[28]),
    u32x4(K32[35], K32[34], K32[33], K32[32]),
    u32x4(K32[39], K32[38], K32[37], K32[36]),
    u32x4(K32[43], K32[42], K32[41], K32[40]),
    u32x4(K32[47], K32[46], K32[45], K32[44]),
    u32x4(K32[51], K32[50], K32[49], K32[48]),
    u32x4(K32[55], K32[54], K32[53], K32[52]),
    u32x4(K32[59], K32[58], K32[57], K32[56]),
    u32x4(K32[63], K32[62], K32[61], K32[60]),
];

pub static H256: [u32; STATE_LEN] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
