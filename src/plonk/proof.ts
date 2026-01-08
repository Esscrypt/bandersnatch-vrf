/**
 * Plonk Proof Structure
 * 
 * Matches w3f-plonk-common/src/lib.rs Proof type
 */

/**
 * Plonk Proof
 * 
 * Contains all commitments and evaluations needed for verification
 */
export interface Proof<Commitments, Evaluations> {
  /** Commitments to witness columns */
  columnCommitments: Commitments
  /** Column evaluations at zeta */
  columnsAtZeta: Evaluations
  /** Quotient polynomial commitment */
  quotientCommitment: Uint8Array
  /** Linearization polynomial evaluated at zeta*omega */
  linAtZetaOmega: bigint
  /** Aggregated KZG proof at zeta */
  aggAtZetaProof: Uint8Array
  /** Linearization KZG proof at zeta*omega */
  linAtZetaOmegaProof: Uint8Array
}

