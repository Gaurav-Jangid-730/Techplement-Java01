import File_Handling.EncryptionDecryptionManager;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class cryptographic_Tool {
    public static void main(String[] args) {
        Map<String, String> arguments = parseArguments(args);

        if (arguments.containsKey("help") || arguments.isEmpty()) {
            printHelp();
            return;
        }

        String algorithm = arguments.get("algorithm");
        String mode = arguments.get("mode");
        File inputFile = new File(arguments.get("input"));
        File outputFile = new File(arguments.get("output"));
        File keyFile = null;
        if(arguments.containsKey("key")) keyFile = new File(arguments.get("key"));
        int keysize=0;
        if(arguments.containsKey("keysize")) keysize= Integer.parseInt(arguments.get("keysize"));
        boolean verbose = arguments.containsKey("verbose");

        try {
            EncryptionDecryptionManager manager = new EncryptionDecryptionManager();
            if ("encrypt".equalsIgnoreCase(mode)) {
                manager.encryptFile(algorithm, inputFile, outputFile, keysize, verbose);
            } else if ("decrypt".equalsIgnoreCase(mode)) {
                manager.decryptFile(algorithm, inputFile, outputFile, keyFile, verbose);
            } else {
                System.out.println("Invalid mode. Use 'encrypt' or 'decrypt'.");
                printHelp();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Map<String, String> parseArguments(String[] args) {
        Map<String, String> arguments = new HashMap<>();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-a":
                case "--algorithm":
                    arguments.put("algorithm", args[++i]);
                    break;
                case "-m":
                case "--mode":
                    arguments.put("mode", args[++i]);
                    break;
                case "-i":
                case "--input":
                    arguments.put("input", args[++i]);
                    break;
                case "-o":
                case "--output":
                    arguments.put("output", args[++i]);
                    break;
                case "-k":
                case "--key":
                    arguments.put("key", args[++i]);
                    break;
                case "-v":
                case "--verbose":
                    arguments.put("verbose", "true");
                    break;
                case "-h":
                case "--help":
                    arguments.put("help", "true");
                    break;
                case "-ks":
                case "--keysize":
                    arguments.put("keysize", args[++i]);
                    break;
                default:
                    System.out.println("Unknown argument: " + args[i]);
                    printHelp();
                    break;
            }
        }

        return arguments;
    }

    private static void printHelp() {
        System.out.println("Usage: java -jar EncryptionTool.jar [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -a, --algorithm <algorithm>   Specify the encryption algorithm to use (ChaCha20, AES, RSA, Blowfish, Twofish).");
        System.out.println("  -m, --mode <mode>             Specify the mode (encrypt or decrypt).");
        System.out.println("  -i, --input <file>            Specify the input file.");
        System.out.println("  -o, --output <file>           Specify the output file.");
        System.out.println("  -k, --key <file>              Specify the key file.");
        System.out.println("  -ks, --keysize <nonce>        Specify key size (for applicable algorithms).");
        System.out.println("  -v, --verbose                 (Optional) Enable verbose mode for detailed output.");
        System.out.println("  -h, --help                    Display this help message.");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  Encrypt a file using ChaCha20:");
        System.out.println("    java -jar EncryptionTool.jar -a ChaCha20 -m encrypt -i input.txt -o output.enc -k keyfile.key");
        System.out.println();
        System.out.println("  Decrypt a file using ChaCha20:");
        System.out.println("    java -jar EncryptionTool.jar -a ChaCha20 -m decrypt -i output.enc -o decrypted.txt -k keyfile.key");
    }
}
