import java.util.Base64;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.math.ec.rfc7748.X25519;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Escrow (.vaultkey) cross-platform vector generator — mirrors Android VaultEscrow.export().
 * Emits TWO variants:
 *   1) SEED format  — payload := xPriv(32) || seed(64) || pubMlkem(1184) || pubX25519(32)
 *      (the cross-platform escrow format; iOS restores via seedRepresentation)
 *   2) EXPANDED format — payload := xPriv(32) || expanded(2400) || pubMlkem(1184) || pubX25519(32)
 *      (Android v1.0 current behavior via getExpanded; documents the legacy case)
 *
 * Also encrypts one QVAULT v2 file with the same keys so the restored vault
 * can be proven by decrypting it.
 */
public class QVaultEscrowVectorGen {
    static final byte[] MAGIC = {0x56, 0x4B, 0x45, 0x59, 0x31, 0x00}; // "VKEY1\0"
    static final byte[] QMAGIC = {0x51, 0x56, 0x41, 0x55, 0x4C, 0x54}; // "QVAULT"
    static final int FORMAT_V2 = 2;
    static final int IV_LEN = 12;
    static final int GCM_TAG_BITS = 128;
    static final String PASSPHRASE = "escrow-recovery-passphrase";

    public static void main(String[] args) throws Exception {
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(new byte[]{0x51, 0x56, 0x41, 0x55, 0x4C, 0x54, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09});

        // Vault keypair (same deterministic stream as other vectors)
        MLKEMKeyPairGenerator kemGen = new MLKEMKeyPairGenerator();
        kemGen.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kemPair = kemGen.generateKeyPair();
        MLKEMPrivateKeyParameters kemPriv = (MLKEMPrivateKeyParameters) kemPair.getPrivate();
        MLKEMPublicKeyParameters kemPub = (MLKEMPublicKeyParameters) kemPair.getPublic();
        byte[] pubMlkem = kemPub.getEncoded();

        X25519KeyPairGenerator xGen = new X25519KeyPairGenerator();
        xGen.init(new KeyGenerationParameters(rng, 255));
        AsymmetricCipherKeyPair xPair = xGen.generateKeyPair();
        X25519PrivateKeyParameters xPriv = (X25519PrivateKeyParameters) xPair.getPrivate();
        X25519PublicKeyParameters xPub = (X25519PublicKeyParameters) xPair.getPublic();
        byte[] xPrivRaw = new byte[X25519PrivateKeyParameters.KEY_SIZE];
        xPriv.encode(xPrivRaw, 0);
        byte[] pubX = xPub.getEncoded();

        byte[] seed = kemPriv.getSeed();
        byte[] expanded = kemPriv.getEncoded();

        // ── Encrypted v2 file with these keys (for restore→decrypt proof) ──
        byte[] fileKey = new byte[32];
        rng.nextBytes(fileKey);
        byte[] plaintext = "Escrow-restore cross-platform: Android keys, iOS decrypt".getBytes("UTF-8");
        byte[] payloadIv = new byte[IV_LEN];
        rng.nextBytes(payloadIv);
        Cipher pc = Cipher.getInstance("AES/GCM/NoPadding");
        pc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, payloadIv));
        byte[] payloadCt = pc.doFinal(plaintext);

        X25519PrivateKeyParameters eph = new X25519PrivateKeyParameters(rng);
        byte[] ephPub = eph.generatePublicKey().getEncoded();
        byte[] sharedClassical = new byte[X25519.SCALAR_SIZE];
        eph.generateSecret(xPub, sharedClassical, 0);
        SecretWithEncapsulation kem = new MLKEMGenerator(rng).generateEncapsulated(kemPub);
        byte[] sharedPQ = kem.getSecret();
        byte[] encapsulation = kem.getEncapsulation();
        byte[] salt = new byte[32];
        rng.nextBytes(salt);
        byte[] combined = new byte[sharedClassical.length + sharedPQ.length];
        System.arraycopy(sharedClassical, 0, combined, 0, sharedClassical.length);
        System.arraycopy(sharedPQ, 0, combined, sharedClassical.length, sharedPQ.length);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(combined, salt, "aiguru-pq-hybrid-v1".getBytes("UTF-8")));
        byte[] kek = new byte[32];
        hkdf.generateBytes(kek, 0, kek.length);
        byte[] wrappedDevice = gcmWrap(kek, fileKey, rng);
        byte[] argonSalt = new byte[32];
        rng.nextBytes(argonSalt);
        byte[] passKek = argon2id(PASSPHRASE.toCharArray(), argonSalt);
        byte[] wrappedPass = gcmWrap(passKek, fileKey, rng);

        byte[] qblob = QMAGIC.clone();
        qblob = append(qblob, (byte) FORMAT_V2);
        qblob = append(qblob, ephPub);
        qblob = append(qblob, encapsulation);
        qblob = append(qblob, salt);
        qblob = append(qblob, argonSalt);
        qblob = append(qblob, wrappedDevice);
        qblob = append(qblob, wrappedPass);
        qblob = append(qblob, payloadIv);
        qblob = append(qblob, payloadCt);

        // ── Escrow blobs (both variants) ──
        byte[] seedPayload = concat(xPrivRaw, concat(seed, concat(pubMlkem, pubX)));
        byte[] expandedPayload = concat(xPrivRaw, concat(expanded, concat(pubMlkem, pubX)));

        byte[] escrowSeed = buildEscrow(seedPayload, rng);
        byte[] escrowExpanded = buildEscrow(expandedPayload, rng);

        System.out.println("=== QVAULT ESCROW CROSS-PLATFORM VECTORS ===");
        System.out.println("passphrase: " + PASSPHRASE);
        System.out.println("seed_len: " + seed.length);
        System.out.println("expanded_len: " + expanded.length);
        System.out.println("escrow_seed_b64: " + Base64.getEncoder().encodeToString(escrowSeed));
        System.out.println("escrow_expanded_b64: " + Base64.getEncoder().encodeToString(escrowExpanded));
        System.out.println("qvault_v2_blob_b64: " + Base64.getEncoder().encodeToString(qblob));
        System.out.println("kexPriv_b64: " + Base64.getEncoder().encodeToString(xPrivRaw));
    }

    /** .vaultkey: magic(6) | argonSalt(32) | AES-GCM(passKek, payload) [iv‖ct‖tag] */
    static byte[] buildEscrow(byte[] payload, SecureRandom rng) throws Exception {
        byte[] argonSalt = new byte[32];
        rng.nextBytes(argonSalt);
        byte[] kek = argon2id(PASSPHRASE.toCharArray(), argonSalt);
        byte[] ct = gcmWrap(kek, payload, rng);
        byte[] out = MAGIC.clone();
        out = append(out, argonSalt);
        out = append(out, ct);
        return out;
    }

    /** Argon2id t=3, m=64MiB, p=1, v0x13 — matches Android PassphraseKDF. */
    static byte[] argon2id(char[] passphrase, byte[] salt) {
        Argon2Parameters p = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(3)
            .withMemoryAsKB(64 * 1024)
            .withParallelism(1)
            .withSalt(salt)
            .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(p);
        byte[] out = new byte[32];
        gen.generateBytes(passphrase, out, 0, out.length);
        return out;
    }

    static byte[] gcmWrap(byte[] key, byte[] data, SecureRandom rng) throws Exception {
        byte[] iv = new byte[IV_LEN];
        rng.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = c.doFinal(data);
        byte[] out = new byte[IV_LEN + ct.length];
        System.arraycopy(iv, 0, out, 0, IV_LEN);
        System.arraycopy(ct, 0, out, IV_LEN, ct.length);
        return out;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    static byte[] append(byte[] a, byte b) {
        byte[] r = new byte[a.length + 1];
        System.arraycopy(a, 0, r, 0, a.length);
        r[a.length] = b;
        return r;
    }

    static byte[] append(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}