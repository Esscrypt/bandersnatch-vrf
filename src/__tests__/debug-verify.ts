import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { bytesToHex, hexToBytes, type Hex } from 'viem'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { Bandersnatch, BandersnatchCurve, BANDERSNATCH_PARAMS } from '@pbnjam/bandersnatch'
import { RingVRFProver, type RingVRFInput } from '../prover/ring-kzg'
import { PedersenVRFProver } from '../prover/pedersen'
import { PiopParams } from '../plonk/piop/params'
import { PiopProver } from '../plonk/piop/prover'
import { PiopVerifier } from '../plonk/piop/verifier'
import { Domain } from '../plonk/domain/domain'
import { SimplePlonkTranscript } from '../plonk/transcript/transcript'
import { PlonkProver } from '../plonk/prover'
import { PlonkVerifier } from '../plonk/verifier'
import { bigintToBytes32BE, commitPolynomialCoeffs } from '../utils/kzg-manual'
import { loadSRSFromFile } from '../utils/srs-loader'
import { bytesToBigIntLittleEndian } from '../crypto/elligator2'
import type { FixedColumnsCommitted } from '../plonk/piop/mod'

const testVectorsPath = join(__dirname, './vectors/bandersnatch_sha-512_ell2_ring.json')
const vectors = JSON.parse(readFileSync(testVectorsPath, 'utf-8'))
const vector = vectors[0]

function parseRingKeys(ringPksHex: string): Uint8Array[] {
  const keySize = 32
  const normalizedHex = ringPksHex.startsWith('0x') ? ringPksHex : `0x${ringPksHex}`
  const ringPksBytes = hexToBytes(normalizedHex as Hex)
  const keys: Uint8Array[] = []
  for (let i = 0; i < ringPksBytes.length; i += keySize) {
    keys.push(ringPksBytes.slice(i, i + keySize))
  }
  return keys
}

const skHex = vector.sk.startsWith('0x') ? vector.sk : `0x${vector.sk}`
const pkHex = vector.pk.startsWith('0x') ? vector.pk : `0x${vector.pk}`
let alphaHex = '0x'
if (vector.alpha) alphaHex = vector.alpha.startsWith('0x') ? vector.alpha : `0x${vector.alpha}`
let adHex = '0x'
if (vector.ad) adHex = vector.ad.startsWith('0x') ? vector.ad : `0x${vector.ad}`

const secretKey = hexToBytes(skHex as `0x${string}`)
const publicKey = hexToBytes(pkHex as `0x${string}`)
const inputBytes = hexToBytes(alphaHex as `0x${string}`)
const auxData = hexToBytes(adHex as `0x${string}`)
const ringKeys = parseRingKeys(vector.ring_pks)
let proverIndex = -1
for (let i = 0; i < ringKeys.length; i++) {
  if (bytesToHex(ringKeys[i]) === bytesToHex(publicKey)) { proverIndex = i; break }
}

const srsFilePath = join(__dirname, 'test-data/srs/zcash-srs-2-11-uncompressed.bin')
const [srsErr, srsResult] = loadSRSFromFile(srsFilePath)
if (srsErr) throw srsErr

const MODULUS_BIT_SIZE = 255
const ringSize = 8
const piopDomainSize = 2 ** Math.ceil(Math.log2(ringSize + 4 + MODULUS_BIT_SIZE))
const pcsDomainSize = 3 * piopDomainSize + 1
const srsG1Points = srsResult.g1Points.slice(0, pcsDomainSize)
const SUITE_ID = 'Bandersnatch_SHA-512_ELL2'

const domain = new Domain(piopDomainSize, true)
const h = { x: BANDERSNATCH_PARAMS.BLINDING_BASE.x, y: BANDERSNATCH_PARAMS.BLINDING_BASE.y }
const seed = PiopParams.getAccumulatorSeedPoint()
const padding = PiopParams.getPaddingPoint()
const piopParams = PiopParams.setup(domain, h, seed, padding)

// Parse ring keys
function hexToUint8(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}
const PADDING_POINT_HEX = '0x92ca79e61dd90c1573a8693f199bf6e1e86835cc715cdcf93f5ef222560023aa'
const paddingBytes = hexToUint8(PADDING_POINT_HEX)
const paddingPoint = BandersnatchCurve.bytesToPoint(paddingBytes)
const paddingXY = { x: paddingPoint.x, y: paddingPoint.y }

const parsedKeys: Array<{ x: bigint; y: bigint }> = []
for (const keyBytes of ringKeys) {
  try {
    const point = BandersnatchCurve.bytesToPoint(keyBytes)
    parsedKeys.push({ x: point.x, y: point.y })
  } catch {
    parsedKeys.push(paddingXY)
  }
}

const maxRing = Math.max(0, piopDomainSize - (4 + MODULUS_BIT_SIZE))
const keysToUse = parsedKeys.length <= maxRing ? parsedKeys : parsedKeys.slice(0, maxRing)

const fixedColumns = piopParams.fixedColumns(keysToUse)

// Compute blinding factor
const pedersenResult = PedersenVRFProver.prove(secretKey, { input: inputBytes, auxData })
const blindingScalar = bytesToBigIntLittleEndian(pedersenResult.blindingFactor)

// Build PIOP prover
const piopProver = PiopProver.build(piopParams, fixedColumns, proverIndex, blindingScalar)

// Get the result (Y_bar) from the prover
const resultXY = piopProver.result()
console.log('piop.result() x:', resultXY.x.toString(16).slice(0, 20) + '...')

// Compute ring commitment
const prover = new RingVRFProver(srsFilePath, 8)
const ringCommitmentBytes = prover.computeRingCommitment(ringKeys)
const fixedColumnsCommitted: FixedColumnsCommitted = {
  points: [ringCommitmentBytes.slice(0, 48), ringCommitmentBytes.slice(48, 96)],
  ringSelector: ringCommitmentBytes.slice(96, 144),
}

// --- Prover side ---
const serVk = (vk: any) => {
  const buf = new Uint8Array(384)
  let o = 0
  buf.set(vk.pcsRawVk.g1, o); o += 48
  buf.set(vk.pcsRawVk.g2, o); o += 96
  buf.set(vk.pcsRawVk.tauInG2, o); o += 96
  buf.set(vk.fixedColumnsCommitted.points[0], o); o += 48
  buf.set(vk.fixedColumnsCommitted.points[1], o); o += 48
  buf.set(vk.fixedColumnsCommitted.ringSelector, o)
  return buf
}

const verifierKeyObj = {
  pcsRawVk: { g1: srsResult.g1, g2: srsResult.g2, tauInG2: srsResult.g2Points[1]! },
  fixedColumnsCommitted,
}
const vkBytes = serVk(verifierKeyObj)

// Run prover
const pcsCk = { srsG1Points, srsG1: srsResult.g1, srsG2: srsResult.g2, srsG2Tau: srsResult.g2Points[1]! }
const proverTranscript = SimplePlonkTranscript.new(SUITE_ID)
const plonkProver = PlonkProver.init(pcsCk, vkBytes, proverTranscript)

console.log('\nProving...')
const proof = plonkProver.prove(piopProver)
console.log('Proof generated successfully')
console.log('linAtZetaOmega:', proof.linAtZetaOmega.toString(16).slice(0, 20) + '...')

// --- Verifier side ---
const pcsVk = { srsG1: srsResult.g1, srsG2: srsResult.g2, srsG2Tau: srsResult.g2Points[1]! }
const verifierTranscript = SimplePlonkTranscript.new(SUITE_ID)
const plonkVerifier = PlonkVerifier.init(pcsVk, vkBytes, verifierTranscript)

// Get Y_bar bytes
const pedersenComponents = PedersenVRFProver.deserialize(pedersenResult.proof)
const yBar = pedersenComponents.Y_bar
const keyCommitmentPoint = BandersnatchCurve.bytesToPoint(yBar)

const nConstraints = PiopVerifier.N_CONSTRAINTS
const nPolys = PiopVerifier.N_COLUMNS + 1

const challenges = plonkVerifier.restoreChallenges(yBar, proof, nPolys, nConstraints)
console.log('\nChallenges:')
console.log('  zeta:', challenges.zeta.toString(16).slice(0, 20) + '...')
console.log('  alphas[0]:', challenges.alphas[0]?.toString(16).slice(0, 20) + '...')
console.log('  nus[0]:', challenges.nus[0]?.toString(16).slice(0, 20) + '...')
console.log('  nus[1]:', challenges.nus[1]?.toString(16).slice(0, 20) + '...')

// seed + result
const seedP = Bandersnatch.fromAffine({ x: piopParams.seed.x, y: piopParams.seed.y })
const seedPlusResult = BandersnatchCurve.add(seedP, keyCommitmentPoint)

const domainEvals = piopParams.domain.evaluate(challenges.zeta)
console.log('\nDomain evals:')
console.log('  lFirst:', domainEvals.lFirst.toString(16).slice(0, 20) + '...')
console.log('  lLast:', domainEvals.lLast.toString(16).slice(0, 20) + '...')
console.log('  vanishingPolyInv:', domainEvals.vanishingPolynomialInv.toString(16).slice(0, 20) + '...')

const piopVerifier = PiopVerifier.init(
  domainEvals,
  fixedColumnsCommitted,
  proof.columnCommitments,
  proof.columnsAtZeta,
  [piopParams.seed.x, piopParams.seed.y],
  [seedPlusResult.x, seedPlusResult.y],
)

const qZeta = piopVerifier.evaluateQAtZeta(challenges.alphas, proof.linAtZetaOmega)
console.log('\nqZeta:', qZeta.toString(16).slice(0, 20) + '...')

// Compute what qZeta should be from the prover's quotient polynomial
// qZeta_expected = quotientPoly.evaluate(zeta)
// But we don't have access to quotientPoly here. Let's check the full verify instead.
const verifyResult = plonkVerifier.verify(piopVerifier, proof, challenges)
console.log('\nVerify result:', verifyResult)
