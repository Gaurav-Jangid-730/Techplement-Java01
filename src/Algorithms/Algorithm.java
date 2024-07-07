package Algorithms;

import javax.crypto.SecretKey;
import java.io.File;
import java.security.NoSuchAlgorithmException;

public interface Algorithm {
    public SecretKey generateKey(int keySize) throws NoSuchAlgorithmException, Exception;
    public void encryptFile(File inFile, File outFile, SecretKey key, boolean verbose) throws Exception;
    public void decryptFile(File inputFile, File outputFile, SecretKey key, boolean verbose) throws Exception;
    public String keyToString(SecretKey key);
    public SecretKey stringToKey(String keyString);
}
