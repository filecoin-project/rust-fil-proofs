pub trait Vdf {
    type SetupParams;
    type PublicParams;
    type PublicParams;
    type SourceDomain;
    type TargetDomain;
    type Proof;

    fn setup(&Self::SetupParams, t: u64) -> Result<Self::PublicParams>;
    fn eval(&Self::PublicParams, x: &Self::SourceDomain) -> Result<(Self::TargetDomain, Self::Proof)>;
    fn verify(&Self::PublicParams, x: &Self::SourceDomain, y: &Self::TargetDomain, proof: Self::Proof) -> Result<bool>;
}

pub trait PoST {
    type Vdf: Vdf;
    type ProofScheme: ProofScheme;

    /// PoST.Setup(1^{\lambda}, M) -> pp
    fn setup(
        sp_vdf: &Self::Vdf::SetupParams,
        sp_ps: &Self::ProofScheme::SetupParams,
        t: u64,
    ) -> Result<(Self::Vdf::PublicParams, Self::ProofScheme::PublicParms)> {
        // TODO: where doe these come from?
        let (m, n) = get_m_n();

        // PoRep.Setup(1^{\lambda}, T)
        let pp_ps = Self::ProofScheme::setup(sp_ps)?;

        // VDF.Setup(1^{\lambda}, \frac{T}{(n-1) * m})
        let pp_vdf = Self::Vdf::setup(sp_vdf, t / ((n - 1) * m))?;

        // pp
        Ok((pp_vdf, sp_ps))
    }

    /// PoST.Prove(D, t_i, B_i) -> \pi^i
    fn prove(
        pp_ps: Self::ProofScheme::PublicParams,
        pp_vdf: Self::Vdf::PublicParams,
        pub_inputs_ps: Self::ProofScheme::PublicInputs,
        priv_inputs_ps: Self::ProofScheme::PrivateInputs,
        // TODO: what is t_i?
        t_i: u64
    ) -> Result<(Vec<Self::Vdf::Proof>, Vec<Self::ProofScheme::Proof>)> {
        // Step 1

        // B_i <- Beacon(t_i)
        let b_i = beacon(t_i);

        // TODO: where does l come from?
        let l = get_l();

        // TODO: units, bytes, vs ?


        // derive a challenge vector c_1^i
        let c_1_i: Vec<u64> = (0..l).map(|j| {
            // c_{1, j}^i := H(B_i || j)
            Self::hash([b_i, j].concat())
        }).collect();

        let mut proofs = Vec::with_capacity(n);

        // \pi_1^i <- PoRep.Prove(R, aux, id, c_1^i)
        proofs.push(Self::ProofScheme::prove(R, id, c_1_i)?);

        // Step 2
        let mut proofs_vdf = Vec_with_capacity(n-1) ;

        for k in 2..n {
            // x_k <- H(\pi_{k-1}^i)
            let x_k = Self::hash(proofs[k-1]);

            // evaluate (v_k^i, \pi_k^{VDF}) <- VDF.eval(pp, x_k)
            let (v_k_i, proof_k_vdf) = Self::Vdf.eval(pp_vdf, x_k)?;
            proofs_vdf.push(proof_k_vdf);

            // generate a challenge vector
            let c_k_i: Vec<u64> = (0..l).map(|j| {
                // c_{k, j}^i := H(v_k^i || j)
                Self::hash([v_k_i, j].concat())
            }).collect();

            // \pi_k^i <- PoRep.Prove(R, aux, id, c_k^i)
            proofs.push(Self::ProofScheme::prove(R, id, c_k_i)?);
        }

        Ok((proofs_vdf, proofs))
    }

    // PoST.Verify(c^i, t_i, \pi^i, (v^i, \pi^{VDF}))
    fn verify(proofs_vdf: Vec<Self::Vdf::Proof>, proofs: Vec<Self::ProofScheme::Proof>) -> Result<bool> {
        // -- VDF Output Verificateion
        for k in 2..n {
            if !Self::Vdf::verify(pp, t_i[k], x_k, v_k_i, proofs_vdf[k - 1])? {
                return Ok(false);
            }
        }

        // -- Challenge Verification

        // k = 1

        // k in 2..n
        for k in 2..n {

        }

        // -- PoRep Verification

        for proof in &proofs {
            if !Self::ProofScheme::verify(pub_params, pub_inputs, proof)? {
                return Ok(false);
            }
        }
    }

    /// Beacon function
    fn beacon(t_i: u64) -> u64;

    /// Hash function
    fn hash(&[u8]) -> &[u8];
}
