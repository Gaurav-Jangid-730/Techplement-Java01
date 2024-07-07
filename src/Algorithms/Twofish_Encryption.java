package Algorithms;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class Twofish_Encryption implements Algorithm {
    public SecretKey generateKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("Twofish");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    public void encryptFile(File inFile, File outFile, SecretKey key, boolean verbose) throws Exception {
        Cipher cipher = Cipher.getInstance("Twofish");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        try (FileInputStream inStream = new FileInputStream(inFile);
             FileOutputStream outStream = new FileOutputStream(outFile)) {
            byte[] buffer = new byte[1024];
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

    public void decryptFile(File inputFile, File outputFile, SecretKey key, boolean verbose) throws Exception {
        Cipher cipher = Cipher.getInstance("Twofish");
        cipher.init(Cipher.DECRYPT_MODE, key);

        try (FileInputStream inStream = new FileInputStream(inputFile);
             FileOutputStream outStream = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[1024];
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
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "Twofish");
    }
}
