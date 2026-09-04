import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;

/** Verify BC 1.85 auto-detects seed (64B) vs expanded (2400B) in the
 *  (params, byte[]) constructor — the path Android restore uses for escrow imports. */
public class BCSeedInterop {
    public static void main(String[] args) throws Exception {
        SecureRandom rng = new SecureRandom();
        MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
        g.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kp = g.generateKeyPair();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters) kp.getPrivate();
        MLKEMPublicKeyParameters pub = (MLKEMPublicKeyParameters) kp.getPublic();

        byte[] seed = priv.getSeed();
        byte[] expanded = priv.getEncoded();
        System.out.println("seed_len=" + seed.length + " expanded_len=" + expanded.length);

        // encapsulate against the public key
        SecretWithEncapsulation kem = new MLKEMGenerator(rng).generateEncapsulated(pub);
        byte[] ss = kem.getSecret();
        byte[] enc = kem.getEncapsulation();

        // 1) reconstruct from SEED via (params, byte[]) constructor
        MLKEMPrivateKeyParameters fromSeed = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, seed);
        byte[] ss1 = new MLKEMExtractor(fromSeed).extractSecret(enc);
        System.out.println("seed_ctor: " + (Arrays.equals(ss, ss1) ? "MATCH" : "MISMATCH") + " preferredFormat=" + fromSeed.getPreferredFormat());

        // 2) reconstruct from EXPANDED via same constructor
        MLKEMPrivateKeyParameters fromExp = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, expanded);
        byte[] ss2 = new MLKEMExtractor(fromExp).extractSecret(enc);
        System.out.println("expanded_ctor: " + (Arrays.equals(ss, ss2) ? "MATCH" : "MISMATCH") + " preferredFormat=" + fromExp.getPreferredFormat());

        // 3) SEED_ONLY re-encoding round trip
        byte[] seedEnc = priv.getParametersWithFormat(MLKEMPrivateKeyParameters.SEED_ONLY).getEncoded();
        System.out.println("seed_only_encoded_len=" + seedEnc.length + " equals_seed=" + Arrays.equals(seedEnc, seed));
    }
}
