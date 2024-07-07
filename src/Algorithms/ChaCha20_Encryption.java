package Algorithms;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class ChaCha20_Encryption implements Algorithm {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public SecretKey generateKey(int Size) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
        keyGen.init(Size);
        return keyGen.generateKey();
    }

    public void encryptFile(File inFile, File outFile, SecretKey key, boolean verbose) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        try (FileInputStream inStream = new FileInputStream(inFile);
             FileOutputStream outStream = new FileOutputStream(outFile)) {

            // Generate and write the nonce (IV) to the output file
            byte[] nonce = generateNonce();
            outStream.write(nonce);

            // Initialize cipher with nonce
            cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce,0));

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
        Cipher cipher = Cipher.getInstance("ChaCha20");

        try (FileInputStream inStream = new FileInputStream(inputFile);
             FileOutputStream outStream = new FileOutputStream(outputFile)) {

            // Read nonce (IV) from the input file
            byte[] nonce = new byte[12]; // 12 bytes for ChaCha20 nonce
            inStream.read(nonce);

            // Initialize cipher with nonce
            cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce,0));

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

    private byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[12]; // 12 bytes for ChaCha20 nonce
        random.nextBytes(nonce);
        return nonce;
    }

    public String keyToString(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public SecretKey stringToKey(String keyString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        return new SecretKeySpec(decodedKey, "ChaCha20");
    }
}
