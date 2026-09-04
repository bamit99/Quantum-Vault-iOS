import java.util.Base64;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import java.security.SecureRandom;

public class BCFields {
    public static void main(String[] args) throws Exception {
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(new byte[]{0x51, 0x56, 0x41, 0x55, 0x4C, 0x54, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09});
        MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
        g.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair p = g.generateKeyPair();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters) p.getPrivate();
        System.out.println("s_b64: " + Base64.getEncoder().encodeToString(priv.getS()));
        System.out.println("hpk_b64: " + Base64.getEncoder().encodeToString(priv.getHPK()));
        System.out.println("nonce_b64: " + Base64.getEncoder().encodeToString(priv.getNonce()));
        System.out.println("seed_b64: " + Base64.getEncoder().encodeToString(priv.getSeed()));
        System.out.println("encoded_len: " + priv.getEncoded().length);
        System.out.println("seed_len: " + (priv.getSeed() == null ? -1 : priv.getSeed().length));
        System.out.println("s_len: " + priv.getS().length);
        System.out.println("hpk_len: " + priv.getHPK().length);
        System.out.println("nonce_len: " + priv.getNonce().length);
    }
}
