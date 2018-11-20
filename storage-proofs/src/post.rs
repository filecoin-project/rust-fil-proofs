use error::Result;
use proof::ProofScheme;

pub trait Vdf {
    type SetupParams;
    type PublicParams;
    type Proof;

    fn setup(&Self::SetupParams, t: usize) -> Result<Self::PublicParams>;
    fn eval(&Self::PublicParams, x: &[u8]) -> Result<(Vec<u8>, Self::Proof)>;
    fn verify(&Self::PublicParams, x: &[u8], y: &[u8], proof: Self::Proof) -> Result<bool>;
}

pub trait PoST<'a> {
    type Vdf: Vdf;
    type ProofScheme: ProofScheme<'a>;

    /// PoST.Setup(1^{\lambda}, M) -> pp
    fn setup(
        sp_vdf: &<<Self as PoST<'a>>::Vdf as Vdf>::SetupParams,
        sp_ps: &<<Self as PoST<'a>>::ProofScheme as ProofScheme<'a>>::SetupParams,
        t: usize,
        m: usize,
        n: usize,
        l: usize,
    ) -> Result<(
        <<Self as PoST<'a>>::Vdf as Vdf>::PublicParams,
        <<Self as PoST<'a>>::ProofScheme as ProofScheme<'a>>::PublicParams,
        usize,
        usize,
        usize,
    )> {
        // TODO: where doe these come from?

        // PoRep.Setup(1^{\lambda}, T)
        let pp_ps = Self::ProofScheme::setup(sp_ps)?;

        // VDF.Setup(1^{\lambda}, \frac{T}{(n-1) * m})
        let pp_vdf = Self::Vdf::setup(sp_vdf, t / ((n - 1) * m))?;

        // pp
        Ok((pp_vdf, pp_ps, l, m, n))
    }

    /// PoST.Prove(D, t_i, B_i) -> \pi^i
    fn prove(
        pp: (
            <<Self as PoST<'a>>::ProofScheme as ProofScheme<'a>>::PublicParams,
            <<Self as PoST<'a>>::Vdf as Vdf>::PublicParams,
            usize,
            usize,
            usize,
        ),
        pub_inputs_ps: <<Self as PoST<'a>>::ProofScheme as ProofScheme<'a>>::PublicInputs,
        priv_inputs_ps: <<Self as PoST<'a>>::ProofScheme as ProofScheme<'a>>::PrivateInputs,
        // TODO: what is t_i? I think it is the time step i
        t_i: usize,
    ) -> Result<(
        Vec<Vec<Vec<u8>>>,
        Vec<<<Self as PoST<'a>>::Vdf as Vdf>::Proof>,
        Vec<<<Self as PoST<'a>>::ProofScheme as ProofScheme<'a>>::Proof>,
    )> {
        let (pp_ps, pp_vdf, l, m, n) = pp;

        // Step 1

        // B_i <- Beacon(t_i)
        let b_i = Self::beacon(t_i);

        let mut c_i: Vec<Vec<Vec<u8>>> = Vec::with_capacity(n);
        // derive a challenge vector c_1^i
        c_i.push(
            (0..l)
                .map(|j| {
                    // c_{1, j}^i := H(B_i || j)
                    // TODO: properly convert j to a byte slice
                    Self::hash(&[&b_i[..], &[j as u8][..]].concat())
                })
                .collect(),
        );

        let mut proofs = Vec::with_capacity(n);

        // \pi_1^i <- PoRep.Prove(R, aux, id, c_1^i)
        // TODO: integrate the challenge c_k^i into the pub_inputs_ps
        // e.g. for merklepor this would be pub_inputs_ps.challenge = c_i[1]
        proofs.push(Self::ProofScheme::prove(
            &pp_ps,
            &pub_inputs_ps,
            &priv_inputs_ps,
        )?);

        // Step 2
        let mut proofs_vdf = Vec::with_capacity(n - 1);

        for k in 2..n {
            // x_k <- H(\pi_{k-1}^i)
            let x_k = Self::hash(&proofs[k - 1].serialize());

            // evaluate (v_k^i, \pi_k^{VDF}) <- VDF.eval(pp, x_k)
            let (v_k_i, proof_k_vdf) = Self::Vdf::eval(&pp_vdf, &x_k)?;
            proofs_vdf.push((v_k_i, proof_k_vdf));

            // generate a challenge vector
            c_i.push(
                (0..l)
                    .map(|j| {
                        // c_{k, j}^i := H(v_k^i || j)
                        // TODO: properly convert j to slice
                        Self::hash(&[&v_k_i[..], &[j as u8][..]].concat())
                    })
                    .collect(),
            );

            // \pi_k^i <- PoRep.Prove(R, aux, id, c_k^i)
            // TODO: integrate the challenge c_k^i into the pub_inputs_ps
            // e.g. for merklepor this would be pub_inputs_ps.challenge = c_i[k]
            proofs.push(Self::ProofScheme::prove(
                &pp_ps,
                &pub_inputs_ps,
                &priv_inputs_ps,
            )?);
        }

        Ok((c_i, proofs_vdf, proofs))
    }

    // PoST.Verify(c^i, t_i, \pi^i, (v^i, \pi^{VDF}))
    fn verify(
        pp: (
            <<Self as PoST<'a>>::ProofScheme as ProofScheme<'a>>::PublicParams,
            <<Self as PoST<'a>>::Vdf as Vdf>::PublicParams,
            usize,
            usize,
            usize,
        ),
        pub_inputs_ps: <<Self as PoST<'a>>::ProofScheme as ProofScheme<'a>>::PublicInputs,
        c_i: Vec<Vec<Vec<u8>>>,
        t_i: usize,
        proofs_vdf: Vec<(Vec<u8>, <<Self as PoST<'a>>::Vdf as Vdf>::Proof)>,
        proofs: Vec<<<Self as PoST<'a>>::ProofScheme as ProofScheme<'a>>::Proof>,
    ) -> Result<bool> {
        let (pp_ps, pp_vdf, l, m, n) = pp;

        // -- VDF Output Verification
        for k in 2..n {
            let (v_k_i, proof_vdf_k) = proofs_vdf[k - 1];
            let x_k = Self::hash(&proofs[k - 1].serialize());

            if !Self::Vdf::verify(&pp_vdf, &x_k, &v_k_i, proof_vdf_k)? {
                return Ok(false);
            }
        }

        // -- Challenge Verification
        let b_i = Self::beacon(t_i);

        // k = 1
        for j in 0..l {
            if Self::hash([&b_i, &[j][..]].concat()) != c_i[1][j] {
                return Ok(false);
            }
        }

        // k in 2..n
        for k in 2..n {
            let (v_k_i, _) = proofs_vdf[k - 1];
            for j in 0..l {
                if Self::hash([&v_k_i, &[j][..]].concat()) != c_i[k][j] {
                    return Ok(false);
                }
            }
        }

        // -- PoRep Verification

        for proof in &proofs {
            if !Self::ProofScheme::verify(pp_ps, pub_inputs_ps, proof)? {
                return Ok(false);
            }
        }
    }

    /// Beacon function
    fn beacon(t_i: usize) -> Vec<u8>;

    /// Hash function
    fn hash(&[u8]) -> Vec<u8>;
}
