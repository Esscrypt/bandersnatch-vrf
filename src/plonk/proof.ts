export interface Proof<Commitments, Evaluations> {
  columnCommitments: Commitments
  columnsAtZeta: Evaluations
  quotientCommitment: Uint8Array
  linAtZetaOmega: bigint
  aggAtZetaProof: Uint8Array
  linAtZetaOmegaProof: Uint8Array
}
