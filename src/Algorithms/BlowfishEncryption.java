package Algorithms;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.Base64;

public class BlowfishEncryption {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Key Generation Function
    public static SecretKey generateKey(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish", "BC");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    // File Encryption Function
    public static void encryptFile(File inputFile, File outputFile, SecretKey key) throws Exception {
        validateFile(inputFile);

        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }

    // File Decryption Function
    public static void decryptFile(File inputFile, File outputFile, SecretKey key) throws Exception {
        validateFile(inputFile);

        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             CipherInputStream cis = new CipherInputStream(fis, cipher)) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
        }
    }

    // Utility Function to Convert Key to String
    public static String keyToString(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Utility Function to Convert String to Key
    public static SecretKey stringToKey(String keyString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "Blowfish");
    }

    // Validate File
    private static void validateFile(File file) throws FileNotFoundException {
        if (!file.exists()) {
            throw new FileNotFoundException("File " + file.getPath() + " does not exist.");
        }
        if (!file.isFile()) {
            throw new IllegalArgumentException(file.getPath() + " is not a valid file.");
        }
    }

    // Main method for testing the functionality in an IDE
    public static void main(String[] args) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {

            boolean exit = false;

            while (!exit) {
                System.out.println();
                System.out.println("Choose operation:");
                System.out.println("1. Generate Key");
                System.out.println("2. Encrypt File");
                System.out.println("3. Decrypt File");
                System.out.println("4. Exit");
                System.out.print("Enter your choice (1/2/3/4): ");
                String choice = reader.readLine().trim();

                switch (choice) {
                    case "1":
                        System.out.print("Enter key size (e.g., 128): ");
                        int keySize = Integer.parseInt(reader.readLine().trim());
                        SecretKey key = generateKey(keySize);
                        System.out.println("Generated Key: " + keyToString(key));
                        break;

                    case "2":
                        System.out.print("Enter input file path (plaintext): ");
                        File inputFile = new File(reader.readLine().trim());

                        System.out.print("Enter output file path (encrypted): ");
                        File encryptedFile = new File(reader.readLine().trim());

                        System.out.print("Enter key string: ");
                        SecretKey encryptKey = stringToKey(reader.readLine().trim());

                        encryptFile(inputFile, encryptedFile, encryptKey);
                        System.out.println("File '" + inputFile.getPath() + "' encrypted to '" + encryptedFile.getPath() + "' successfully.");
                        break;

                    case "3":
                        System.out.print("Enter input file path (encrypted): ");
                        File encryptedInputFile = new File(reader.readLine().trim());

                        System.out.print("Enter output file path (decrypted): ");
                        File decryptedOutputFile = new File(reader.readLine().trim());

                        System.out.print("Enter key string: ");
                        SecretKey decryptKey = stringToKey(reader.readLine().trim());

                        decryptFile(encryptedInputFile, decryptedOutputFile, decryptKey);
                        System.out.println("File '" + encryptedInputFile.getPath() + "' decrypted to '" + decryptedOutputFile.getPath() + "' successfully.");
                        break;

                    case "4":
                        exit = true;
                        System.out.println("Exiting program.");
                        break;

                    default:
                        System.out.println("Invalid choice. Please enter 1, 2, 3, or 4.");
                }
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

/**
 * Choose operation:
 * 1. Generate Key
 * 2. Encrypt File
 * 3. Decrypt File
 * 4. Exit
 * Enter your choice (1/2/3/4): 1
 * Enter key size (e.g., 128): 128
 * Generated Key: ZCnX6jJ5OTF7wqBw8vZ9Ow==
 *
 * Choose operation:
 * 1. Generate Key
 * 2. Encrypt File
 * 3. Decrypt File
 * 4. Exit
 * Enter your choice (1/2/3/4): 2
 * Enter input file path (plaintext): D:\files\plaintext.txt
 * Enter output file path (encrypted): D:\files\encrypted.bin
 * Enter key string: ZCnX6jJ5OTF7wqBw8vZ9Ow==
 * File 'C:\files\plaintext.txt' encrypted to 'C:\files\encrypted.bin' successfully.
 *
 * Choose operation:
 * 1. Generate Key
 * 2. Encrypt File
 * 3. Decrypt File
 * 4. Exit
 * Enter your choice (1/2/3/4): 3
 * Enter input file path (encrypted): D:\files\encrypted.bin
 * Enter output file path (decrypted): D:\files\decrypted.txt
 * Enter key string: ZCnX6jJ5OTF7wqBw8vZ9Ow==
 * File 'C:\files\encrypted.bin' decrypted to 'C:\files\decrypted.txt' successfully.
 *
 * Choose operation:
 * 1. Generate Key
 * 2. Encrypt File
 * 3. Decrypt File
 * 4. Exit
 * Enter your choice (1/2/3/4): 4
 * Exiting program.
 */