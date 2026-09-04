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
 * QVAULT v2 (dual-wrap) cross-platform vector generator — uses the FIXED
 * Android wire order (post 6bc42dc): salt | argonSalt | wrappedDevice | wrappedPass | payload.
 * Output feeds the iOS CrossPlatformTests v2 cases.
 */
public class QVaultVectorGenV2 {
    static final byte[] MAGIC = {0x51, 0x56, 0x41, 0x55, 0x4C, 0x54}; // "QVAULT"
    static final int FORMAT_V2 = 2;
    static final int X25519_PUB_LEN = 32;
    static final int MLKEM768_ENCAP_LEN = 1088;
    static final int SALT_LEN = 32;
    static final int IV_LEN = 12;
    static final int GCM_TAG_BITS = 128;
    static final int FILE_KEY_LEN = 32;
    static final int KEK_LEN = 32;
    static final String HKDF_INFO = "aiguru-pq-hybrid-v1";
    static final String PASSPHRASE = "quantum-vault-cross-test";

    public static void main(String[] args) throws Exception {
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(new byte[]{0x51, 0x56, 0x41, 0x55, 0x4C, 0x54, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09});

        // Vault keypair (same deterministic seed stream as v1 vector)
        MLKEMKeyPairGenerator kemGen = new MLKEMKeyPairGenerator();
        kemGen.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kemPair = kemGen.generateKeyPair();
        MLKEMPrivateKeyParameters kemPriv = (MLKEMPrivateKeyParameters) kemPair.getPrivate();
        MLKEMPublicKeyParameters kemPub = (MLKEMPublicKeyParameters) kemPair.getPublic();

        X25519KeyPairGenerator xGen = new X25519KeyPairGenerator();
        xGen.init(new org.bouncycastle.crypto.KeyGenerationParameters(rng, 255));
        AsymmetricCipherKeyPair xPair = xGen.generateKeyPair();
        X25519PrivateKeyParameters xPriv = (X25519PrivateKeyParameters) xPair.getPrivate();
        X25519PublicKeyParameters xPub = (X25519PublicKeyParameters) xPair.getPublic();
        byte[] xPrivRaw = new byte[X25519PrivateKeyParameters.KEY_SIZE];
        xPriv.encode(xPrivRaw, 0);

        // File key + payload
        byte[] fileKey = new byte[FILE_KEY_LEN];
        rng.nextBytes(fileKey);
        byte[] plaintext = "QVAULT v2 dual-wrap: Android fixed code, iOS decrypt".getBytes("UTF-8");
        byte[] payloadIv = new byte[IV_LEN];
        rng.nextBytes(payloadIv);
        Cipher pc = Cipher.getInstance("AES/GCM/NoPadding");
        pc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, payloadIv));
        byte[] payloadCt = pc.doFinal(plaintext);

        // Classical leg
        X25519PrivateKeyParameters eph = new X25519PrivateKeyParameters(rng);
        byte[] ephPub = eph.generatePublicKey().getEncoded();
        byte[] sharedClassical = new byte[X25519.SCALAR_SIZE];
        eph.generateSecret(xPub, sharedClassical, 0);

        // PQ leg
        SecretWithEncapsulation kem = new MLKEMGenerator(rng).generateEncapsulated(kemPub);
        byte[] sharedPQ = kem.getSecret();
        byte[] encapsulation = kem.getEncapsulation();

        // salt + KEK + wrappedDevice (iv‖ct‖tag)
        byte[] salt = new byte[SALT_LEN];
        rng.nextBytes(salt);
        byte[] combined = new byte[sharedClassical.length + sharedPQ.length];
        System.arraycopy(sharedClassical, 0, combined, 0, sharedClassical.length);
        System.arraycopy(sharedPQ, 0, combined, sharedClassical.length, sharedPQ.length);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(combined, salt, HKDF_INFO.getBytes("UTF-8")));
        byte[] kek = new byte[KEK_LEN];
        hkdf.generateBytes(kek, 0, kek.length);
        byte[] wrappedDevice = gcmWrap(kek, fileKey, rng);

        // argonSalt + wrappedPass (iv‖ct‖tag) — BC Argon2id, same params as PassphraseKDF.kt
        byte[] argonSalt = new byte[32];
        rng.nextBytes(argonSalt);
        byte[] passKek = argon2id(PASSPHRASE.toCharArray(), argonSalt);
        byte[] wrappedPass = gcmWrap(passKek, fileKey, rng);

        // Assemble v2 (fixed wire order): magic | 2 | ephPub | encap | salt | argonSalt | wrappedDevice | wrappedPass | payloadIv | payloadCt
        byte[] out = MAGIC.clone();
        out = append(out, (byte) FORMAT_V2);
        out = append(out, ephPub);
        out = append(out, encapsulation);
        out = append(out, salt);
        out = append(out, argonSalt);
        out = append(out, wrappedDevice);
        out = append(out, wrappedPass);
        out = append(out, payloadIv);
        out = append(out, payloadCt);

        System.out.println("=== QVAULT v2 CROSS-PLATFORM VECTOR (fixed wire order) ===");
        System.out.println("seed_b64: " + Base64.getEncoder().encodeToString(kemPriv.getSeed()));
        System.out.println("kexPriv_b64: " + Base64.getEncoder().encodeToString(xPrivRaw));
        System.out.println("passphrase: " + PASSPHRASE);
        System.out.println("plaintext: " + new String(plaintext, "UTF-8"));
        System.out.println("blob_b64: " + Base64.getEncoder().encodeToString(out));
        System.out.println("blob_len: " + out.length);
    }

    /** iv(12) ‖ ct ‖ tag — matches Android aesGcm(encrypt=true). */
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