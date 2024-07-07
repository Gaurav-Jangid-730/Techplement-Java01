package File_Handling;

import Algorithms.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class EncryptionDecryptionManager {
    private final Map<String, Algorithm> algorithms;

    public EncryptionDecryptionManager() {
        algorithms = new HashMap<>();
        algorithms.put("AES", new AES_Encryption());
        algorithms.put("ChaCha20", new ChaCha20_Encryption());
        algorithms.put("Blowfish", new Blowfish_Encryption());
        algorithms.put("Twofish", new Twofish_Encryption());
    }

    public void encryptFile(String algorithm, File inputFile, File outputFile ,int Size , boolean verbose) throws Exception {
        if(algorithm.equals("RSA")){
            RSA_Encryption rsa = new RSA_Encryption();
            KeyPair key = rsa.generateKeyPair(Size);
            rsa.encryptFile(inputFile,outputFile,key.getPublic(),verbose);
            try(FileOutputStream out = new FileOutputStream(outputFile+".key")){
                out.write(key.getPrivate().getEncoded());
            }
        }
        else {
            Algorithm alg = algorithms.get(algorithm);
            if (alg != null) {
                SecretKey key = alg.generateKey(Size);
                alg.encryptFile(inputFile, outputFile, key, true); // Change 'true' to enable verbose output if needed
                saveKey(alg.keyToString(key), outputFile + ".key");
            } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }
        }
    }

    public void decryptFile(String algorithm, File inputFile, File outputFile, File keyFile , boolean verbose) throws Exception {
        if(algorithm.equals("RSA"))
        {
            PrivateKey privateKey = loadPrivateKey(keyFile);
            RSA_Encryption rsaEncryption = new RSA_Encryption();
            rsaEncryption.decryptFile(inputFile, outputFile, privateKey, verbose);
        }
        else {
            Algorithm alg = algorithms.get(algorithm);
            if (alg != null) {
                SecretKey key = loadKey(keyFile, algorithm);
                alg.decryptFile(inputFile, outputFile, key, true); // Change 'true' to enable verbose output if needed
            } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }
        }
    }

    private PrivateKey loadPrivateKey(File keyFile) throws Exception {
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private void saveKey(String key, String keyFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(keyFilePath)) {
            fos.write(key.getBytes());
        }
    }

    private SecretKey loadKey(File keyFile, String algorithm) throws IOException {
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        byte[] decodedKey = Base64.getDecoder().decode(keyBytes);
        return new SecretKeySpec(decodedKey, algorithm);
    }
}
