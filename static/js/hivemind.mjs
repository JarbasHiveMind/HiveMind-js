// ESM entry point.
//
// hivemind.js is a single CommonJS/browser-global file, and package.json
// pointed its "import" condition straight at it. Node resolves that as CJS, so
// the `import { JarbasHiveMind } from 'hivemind-js'` the readme documents threw
// "Named export not found" — the ESM half of the package was advertised but
// never existed. This wrapper is that half: it re-exports the same objects, so
// there is one implementation and no second copy to drift.

import mod from './hivemind.js';

export const {
    JarbasHiveMind, PasswordHandShake, States,
    encryptAesGcm, decryptAesGcm,
    encryptAesGcmBin, decryptAesGcmBin,
    encodeBitstring, decodeBitstring,
    BIN_TYPES, MSG_TYPE_TO_INT, INT_TO_MSG_TYPE,
    NoiseHandshake, NoiseTransport, NoiseCipherState, NoiseSymmetricState,
    selectNoiseOptions, buildNoisePrologue, canonicalJson,
    derivePskPBKDF2, derivePskArgon2,
    noiseHkdf, x25519, x25519PublicFromPrivate,
    NOISE_PATTERN_XX, NOISE_PATTERN_KK,
    NOISE_SUITE_CHACHA, NOISE_SUITE_AESGCM, NOISE_SUITES_JS
} = mod;

export default mod;
