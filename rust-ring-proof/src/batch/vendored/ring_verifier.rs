use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use w3f_pcs::pcs::{RawVerifierKey, PCS};

use w3f_plonk_common::domain::EvaluatedDomain;
use w3f_plonk_common::piop::VerifierPiop;
use w3f_plonk_common::transcript::PlonkTranscript;
use w3f_plonk_common::verifier::PlonkVerifier;

use crate::batch::vendored::piop::params::PiopParams;
use crate::batch::vendored::piop::{FixedColumnsCommitted, PiopVerifier, VerifierKey};
use crate::batch::vendored::{ArkTranscript, RingProof};

pub struct RingVerifier<F, CS, Jubjub, T = ArkTranscript>
where
    F: PrimeField,
    CS: PCS<F>,
    Jubjub: TECurveConfig<BaseField = F>,
    T: PlonkTranscript<F, CS>,
{
    piop_params: PiopParams<F, Jubjub>,
    fixed_columns_committed: FixedColumnsCommitted<F, CS::C>,
    plonk_verifier: PlonkVerifier<F, CS, T>,
}

impl<F, CS, Jubjub, T> RingVerifier<F, CS, Jubjub, T>
where
    F: PrimeField,
    CS: PCS<F>,
    Jubjub: TECurveConfig<BaseField = F>,
    T: PlonkTranscript<F, CS>,
{
    pub fn init(
        verifier_key: VerifierKey<F, CS>,
        piop_params: PiopParams<F, Jubjub>,
        empty_transcript: T,
    ) -> Self {
        let pcs_vk = verifier_key.pcs_raw_vk.prepare();
        let plonk_verifier = PlonkVerifier::init(pcs_vk, &verifier_key, empty_transcript);
        Self {
            piop_params,
            fixed_columns_committed: verifier_key.fixed_columns_committed,
            plonk_verifier,
        }
    }

    pub fn verify(&self, proof: RingProof<F, CS>, result: Affine<Jubjub>) -> bool {
        let (challenges, mut rng) = self.plonk_verifier.restore_challenges(
            &result,
            &proof,
            // '1' accounts for the quotient polynomial that is aggregated together with the columns
            PiopVerifier::<F, CS::C, Affine<Jubjub>>::N_COLUMNS + 1,
            PiopVerifier::<F, CS::C, Affine<Jubjub>>::N_CONSTRAINTS,
        );
        let seed = self.piop_params.seed;
        let seed_plus_result = (seed + result).into_affine();
        let domain_eval = EvaluatedDomain::new(
            self.piop_params.domain.domain(),
            challenges.zeta,
            self.piop_params.domain.hiding,
        );

        let piop = PiopVerifier::<_, _, Affine<Jubjub>>::init(
            domain_eval,
            self.fixed_columns_committed.clone(),
            proof.column_commitments.clone(),
            proof.columns_at_zeta.clone(),
            (seed.x, seed.y),
            (seed_plus_result.x, seed_plus_result.y),
        );

        self.plonk_verifier
            .verify(piop, proof, challenges, &mut rng)
    }

    pub fn piop_params(&self) -> &PiopParams<F, Jubjub> {
        &self.piop_params
    }
}

// --- pbnjam extension: expose a proof's KZG openings for cross-proof batch verification ---
use ark_ec::pairing::Pairing;
use w3f_pcs::pcs::kzg::{KzgOpening, KZG};
use w3f_pcs::pcs::Commitment as _;
use w3f_plonk_common::{ColumnsCommited as _, ColumnsEvaluated as _};

impl<E, Jubjub> RingVerifier<E::ScalarField, KZG<E>, Jubjub, ArkTranscript>
where
    E: Pairing,
    Jubjub: TECurveConfig<BaseField = E::ScalarField>,
{
    
    
    
    
    
    
    pub fn openings_for(
        &self,
        proof: RingProof<E::ScalarField, KZG<E>>,
        result: Affine<Jubjub>,
    ) -> [KzgOpening<E>; 2] {
        type C<E> = <KZG<E> as PCS<<E as Pairing>::ScalarField>>::C;

        // mirror RingVerifier::verify: restore Fiat-Shamir challenges and build the PIOP verifier
        let (challenges, _rng) = self.plonk_verifier.restore_challenges(
            &result,
            &proof,
            PiopVerifier::<E::ScalarField, C<E>, Affine<Jubjub>>::N_COLUMNS + 1,
            PiopVerifier::<E::ScalarField, C<E>, Affine<Jubjub>>::N_CONSTRAINTS,
        );
        let seed = self.piop_params.seed;
        let seed_plus_result = (seed + result).into_affine();
        let domain_eval = EvaluatedDomain::new(
            self.piop_params.domain.domain(),
            challenges.zeta,
            self.piop_params.domain.hiding,
        );
        let piop = PiopVerifier::<_, _, Affine<Jubjub>>::init(
            domain_eval,
            self.fixed_columns_committed.clone(),
            proof.column_commitments.clone(),
            proof.columns_at_zeta.clone(),
            (seed.x, seed.y),
            (seed_plus_result.x, seed_plus_result.y),
        );

        // mirror PlonkVerifier::verify: assemble the aggregated opening (@ zeta) and the
        // linearization opening (@ zeta*omega)
        let eval: E::ScalarField = piop
            .evaluate_constraints_main()
            .iter()
            .zip(challenges.alphas.iter())
            .map(|(c, alpha)| *alpha * c)
            .sum();
        let zeta = challenges.zeta;
        let domain_evaluated = piop.domain_evaluated();
        // upstream divide_by_vanishing_poly_in_zeta(p) == p * vanishing_polynomial_inv (pub field)
        let q_zeta = (eval + proof.lin_at_zeta_omega) * domain_evaluated.vanishing_polynomial_inv;

        let mut columns = [
            piop.precommitted_columns(),
            proof.column_commitments.clone().to_vec(),
        ]
        .concat();
        columns.push(proof.quotient_commitment.clone());

        let mut columns_at_zeta = proof.columns_at_zeta.clone().to_vec();
        columns_at_zeta.push(q_zeta);

        let cl = C::<E>::combine(&challenges.nus, &columns);
        let agg_y: E::ScalarField = columns_at_zeta
            .into_iter()
            .zip(challenges.nus.iter())
            .map(|(y, r)| y * r)
            .sum();

        let lin_pieces = piop.constraint_polynomials_linearized_commitments();
        let lin_comm = C::<E>::combine(&challenges.alphas[..3], &lin_pieces);

        let zeta_omega = zeta * domain_evaluated.omega();

        [
            KzgOpening {
                c: cl.0,
                x: zeta,
                y: agg_y,
                proof: proof.agg_at_zeta_proof,
            },
            KzgOpening {
                c: lin_comm.0,
                x: zeta_omega,
                y: proof.lin_at_zeta_omega,
                proof: proof.lin_at_zeta_omega_proof,
            },
        ]
    }
}
