package Algorithms;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class RSA_Encryption{
    public KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    public void encryptFile(File inFile, File outFile, PublicKey publicKey, boolean verbose) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        try (FileInputStream inStream = new FileInputStream(inFile);
             FileOutputStream outStream = new FileOutputStream(outFile)) {
            byte[] buffer = new byte[117];
            int bytesRead;
            while ((bytesRead = inStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    outStream.write(output);
                }
                if (verbose) {
                    System.out.println("Read " + bytesRead + " bytes from input file.");
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                outStream.write(outputBytes);
            }
            if (verbose) {
                System.out.println("Encryption completed.");
            }
        }
    }

    public void decryptFile(File inputFile, File outputFile, PrivateKey privateKey, boolean verbose) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        try (FileInputStream inStream = new FileInputStream(inputFile);
             FileOutputStream outStream = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[128]; // 128 bytes for RSA decryption with OAEP padding
            int bytesRead;
            while ((bytesRead = inStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    outStream.write(output);
                }
                if (verbose) {
                    System.out.println("Read " + bytesRead + " bytes from input file.");
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                outStream.write(outputBytes);
            }
            if (verbose) {
                System.out.println("Decryption completed.");
            }
        }
    }

    public String keyToString(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public SecretKey stringToKey(String keyString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "RSA");
    }
}
