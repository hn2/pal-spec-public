// Shared by the generators of the grant and extension-signing vectors. The reference implementation signs ML-DSA-65 with
// fresh randomness (FIPS 204 hedged mode), so two runs would differ. Here the bodies come from the reference implementation
// and are signed again in the deterministic FIPS 204 mode, so two runs are byte-identical and any verifier still accepts them.
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export async function loadReference(palCore) {
  const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);
  const nm = (p) => pathToFileURL(resolve(palCore, existsSync(resolve(palCore, 'node_modules', p)) ? 'node_modules' : 'packages/protocol/node_modules', p)).href;
  const { ml_dsa65 } = await import(nm('@noble/post-quantum/ml-dsa.js'));
  const sodium = (await import(nm('sodium-native/index.js'))).default;
  return { lib, ml_dsa65, sodium };
}

export function deterministicSigner({ ml_dsa65, sodium }) {
  return ({ domain, dsaContext, body, edSecretKey, dsaSecretKey }) => {
    const msg = Buffer.concat([Buffer.from(domain, 'ascii'), createHash('sha384').update(body).digest()]);
    const sigEd25519 = Buffer.alloc(64);
    sodium.crypto_sign_detached(sigEd25519, msg, edSecretKey);
    const sigMldsa65 = Buffer.from(ml_dsa65.sign(msg, dsaSecretKey, { context: Buffer.from(dsaContext), extraEntropy: false }));
    return { sigEd25519, sigMldsa65 };
  };
}
