import java.util.Base64;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
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
 * Generate QVAULT v1 test vectors for cross-platform validation.
 * Outputs the vault keypair (base64) and a test blob (hex).
 * Run: java -cp bcprov.jar QVaultVectorGen.java
 */
public class QVaultVectorGen {
    // Identical constants to the Android app
    static final byte[] MAGIC = {0x51, 0x56, 0x41, 0x55, 0x4C, 0x54}; // "QVAULT"
    static final int FORMAT_V1 = 1;
    static final int X25519_PUB_LEN = 32;
    static final int MLKEM768_ENCAP_LEN = 1088;
    static final int SALT_LEN = 32;
    static final int IV_LEN = 12;
    static final int GCM_TAG_BITS = 128;
    static final int FILE_KEY_LEN = 32;
    static final int KEK_LEN = 32;
    static final String HKDF_INFO = "aiguru-pq-hybrid-v1";

    public static void main(String[] args) throws Exception {
        // 1. Deterministic vault keypair
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(new byte[]{0x51, 0x56, 0x41, 0x55, 0x4C, 0x54, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09});

        // ML-KEM-768 keypair
        MLKEMKeyPairGenerator kemGen = new MLKEMKeyPairGenerator();
        kemGen.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kemPair = kemGen.generateKeyPair();
        MLKEMPrivateKeyParameters kemPriv = (MLKEMPrivateKeyParameters) kemPair.getPrivate();
        MLKEMPublicKeyParameters kemPub = (MLKEMPublicKeyParameters) kemPair.getPublic();
        byte[] kemPubRaw = kemPub.getEncoded();

        // X25519 keypair
        X25519KeyPairGenerator xGen = new X25519KeyPairGenerator();
        xGen.init(new org.bouncycastle.crypto.KeyGenerationParameters(rng, 255));
        AsymmetricCipherKeyPair xPair = xGen.generateKeyPair();
        X25519PrivateKeyParameters xPriv = (X25519PrivateKeyParameters) xPair.getPrivate();
        X25519PublicKeyParameters xPub = (X25519PublicKeyParameters) xPair.getPublic();
        byte[] xPubRaw = xPub.getEncoded();
        byte[] xPrivRaw = new byte[X25519PrivateKeyParameters.KEY_SIZE];
        xPriv.encode(xPrivRaw, 0);

        // 2. Fresh file key + payload
        byte[] fileKey = new byte[FILE_KEY_LEN];
        rng.nextBytes(fileKey);
        byte[] plaintext = "Hello from Android! Cross-platform QVAULT test vector".getBytes("UTF-8");

        // AES-GCM payload
        byte[] payloadIv = new byte[IV_LEN];
        rng.nextBytes(payloadIv);
        Cipher pc = Cipher.getInstance("AES/GCM/NoPadding");
        pc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, payloadIv));
        byte[] payloadCt = pc.doFinal(plaintext);

        // 3. Ephemeral X25519
        X25519PrivateKeyParameters eph = new X25519PrivateKeyParameters(rng);
        byte[] ephPub = eph.generatePublicKey().getEncoded();
        byte[] sharedClassical = new byte[X25519.SCALAR_SIZE];
        eph.generateSecret(xPub, sharedClassical, 0);

        // 4. ML-KEM-768 encapsulate
        SecretWithEncapsulation kem = new MLKEMGenerator(rng).generateEncapsulated(kemPub);
        byte[] sharedPQ = kem.getSecret();
        byte[] encapsulation = kem.getEncapsulation();

        // 5. KEK = HKDF(classical || PQ, salt)
        byte[] salt = new byte[SALT_LEN];
        rng.nextBytes(salt);
        byte[] combined = new byte[sharedClassical.length + sharedPQ.length];
        System.arraycopy(sharedClassical, 0, combined, 0, sharedClassical.length);
        System.arraycopy(sharedPQ, 0, combined, sharedClassical.length, sharedPQ.length);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(combined, salt, HKDF_INFO.getBytes("UTF-8")));
        byte[] kek = new byte[KEK_LEN];
        hkdf.generateBytes(kek, 0, kek.length);

        // 6. Wrap file key
        Cipher kw = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] kwIv = new byte[IV_LEN];
        rng.nextBytes(kwIv);
        kw.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, kwIv));
        byte[] wrappedFull = kw.doFinal(fileKey); // iv handled separately; doFinal = ct||tag
        byte[] wrappedDevice = new byte[IV_LEN + FILE_KEY_LEN + GCM_TAG_BITS / 8];
        System.arraycopy(kwIv, 0, wrappedDevice, 0, IV_LEN);
        System.arraycopy(wrappedFull, 0, wrappedDevice, IV_LEN, wrappedFull.length);

        // 7. Assemble QVAULT v1
        byte[] out = MAGIC.clone();
        out = append(out, (byte) FORMAT_V1);
        out = append(out, ephPub);
        out = append(out, encapsulation);
        out = append(out, salt);
        out = append(out, wrappedDevice);
        out = append(out, payloadIv);
        out = append(out, payloadCt);

        // 8. Output
        System.out.println("=== QVAULT CROSS-PLATFORM TEST VECTOR ===");
        System.out.println("kexPriv_b64: " + Base64.getEncoder().encodeToString(xPrivRaw));
        System.out.println("kexPub_b64: " + Base64.getEncoder().encodeToString(xPubRaw));
        System.out.println("kemPriv_b64: " + Base64.getEncoder().encodeToString(kemPriv.getEncoded()));
        System.out.println("kemPub_b64: " + Base64.getEncoder().encodeToString(kemPubRaw));
        System.out.println("plaintext: " + new String(plaintext, "UTF-8"));
        System.out.println("blob_hex: " + bytesToHex(out));
        System.out.println("blob_b64: " + Base64.getEncoder().encodeToString(out));
        System.out.println("blob_len: " + out.length);
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

    static final char[] HEX = "0123456789abcdef".toCharArray();
    static String bytesToHex(byte[] b) {
        char[] h = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            h[i * 2] = HEX[(b[i] >> 4) & 0xf];
            h[i * 2 + 1] = HEX[b[i] & 0xf];
        }
        return new String(h);
    }
}