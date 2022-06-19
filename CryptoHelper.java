package net.voids.auth;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class CryptoHelper {

    private final Cipher cipher;
    private final Key key;

    public CryptoHelper(String key, String algo) throws Exception {
        this.key = new SecretKeySpec(key.getBytes(), algo);
        this.cipher = Cipher.getInstance(algo);
    }

    String encrypt(String plaintext) throws Exception {
        if (plaintext == null)
            return null;
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    String decrypt(String encrypted) throws Exception {
        if (encrypted == null)
            return null;
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedValue = Base64.getDecoder().decode(encrypted);
        byte[] decrypted = cipher.doFinal(decodedValue);
        return new String(decrypted);
    }

}
