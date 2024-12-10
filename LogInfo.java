import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;




public class LogInfo{
    String Username;
    String mdp;
    byte[] cy_Username;
    byte[] cy_mdp;
    
    public LogInfo(String pwd, String nom, byte[] cle) {
        this.mdp = pwd;
        this.Username = nom;

    }


    public static IvParameterSpec GenerateIv() {
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return new IvParameterSpec(initializationVector);
    }


    public void Cypher(SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        cy_Username=cipher.doFinal(Username.getBytes(StandardCharsets.UTF_8));
        cy_mdp=cipher.doFinal(mdp.getBytes(StandardCharsets.UTF_8));
    }

   
};