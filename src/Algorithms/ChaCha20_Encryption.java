package Algorithms;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public final class ChaCha20_Encryption {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Function to generate a ChaCha20 key
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20", "BC");
        keyGen.init(256, new SecureRandom());
        return keyGen.generateKey();
    }

    // Function to encrypt a file using ChaCha20
    public static void encryptFile(File inFile, File outFile, SecretKey key) throws Exception {
        byte[] nonce = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        try (FileOutputStream outStream = new FileOutputStream(outFile)) {
            outStream.write(nonce);

            Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
            ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, 0);
            cipher.init(Cipher.ENCRYPT_MODE, key, param);

            try (FileInputStream inStream = new FileInputStream(inFile)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = inStream.read(buffer)) != -1) {
                    byte[] output = cipher.update(buffer, 0, bytesRead);
                    if (output != null) {
                        outStream.write(output);
                    }
                }
                byte[] outputBytes = cipher.doFinal();
                if (outputBytes != null) {
                    outStream.write(outputBytes);
                }
            }
        }
    }

    // Function to decrypt a file using ChaCha20
    public static void decryptFile(File inputFile, File outputFile, SecretKey key) throws Exception {
        try (FileInputStream inStream = new FileInputStream(inputFile)) {
            byte[] nonce = new byte[12];
            int bytesRead = 0;
            while (bytesRead < nonce.length) {
                int read = inStream.read(nonce, bytesRead, nonce.length - bytesRead);
                if (read == -1) {
                    throw new IllegalArgumentException("Unable to read nonce from input file.");
                }
                bytesRead += read;
            }

            Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
            ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, 0);
            cipher.init(Cipher.DECRYPT_MODE, key, param);

            try (FileOutputStream outStream = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int read;
                while ((read = inStream.read(buffer)) != -1) {
                    byte[] output = cipher.update(buffer, 0, read);
                    if (output != null) {
                        outStream.write(output);
                    }
                }
                byte[] outputBytes = cipher.doFinal();
                if (outputBytes != null) {
                    outStream.write(outputBytes);
                }
            }
        }
    }

    // Function to convert a SecretKey to a Base64 encoded string
    public static String keyToString(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Function to convert a Base64 encoded string to a SecretKey
    public static SecretKey stringToKey(String keyString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "ChaCha20");
    }
}
