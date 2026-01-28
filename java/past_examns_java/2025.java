import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class Main {

    // Use this static variables to hardcode algorithm names and other important values
    private static final String HASH_ALGORITHM = "MD5";
    private static final String HMAC_ALGORITHM = "";
    private static final String SHARED_SECRET = "!q\\Qfald]Qyr1234"; // Secret key for HMAC authentication from the Excel file
    private static final String AES_ALGORITHM = "AES";
    private static final String FOLDER_PATH = "messages";


    // Step 1: Generate Digest values of all the files from the given folder
    public static void generateFilesDigest(String folderPath) throws Exception {
        File folder = new File(folderPath);
        File digests = new File("digests");
        if (!digests.exists()) {
            digests.mkdir();
        }

        for (var f : folder.listFiles()) {
            File out = new File(
                    "digests\\" + f.getName().substring(0, f.getName().length() - 3) + "digest"
            );
            if (out.exists()) {
                continue;
            }
            try (var fis = new FileInputStream(f); var fos = new FileWriter(out)) {

                MessageDigest md = MessageDigest.getInstance("MD5");
                var digest = md.digest(fis.readAllBytes());
                for (int i = 0; i < digest.length; i++) {
                    fos.write(String.format("%02X", digest[i]));
                }
            }
        }
    }

    public static byte[] getMAC(String fileName, String secretKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        File file = new File(fileName);
        if (!file.exists())
            throw new RuntimeException("**** NO FILE *****");

        //init the MAC
        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec macKey = new SecretKeySpec(
                secretKey.getBytes(), "HmacSHA1");
        mac.init(macKey);


        FileInputStream fis = new FileInputStream(file);

        // process the file in blocks
        byte[] buffer = new byte[4];
        while (true) {
            int noBytesFromFile = fis.read(buffer);
            if (noBytesFromFile == -1)
                break;
            mac.update(buffer, 0, noBytesFromFile);
        }

        fis.close();

        return mac.doFinal();
    }

    // Step 2: Generate HMAC-SHA256 authentication code
    public static void generateFilesHMAC(String folderPath, String secretKey) throws Exception {
        File folder = new File(folderPath);
        File digests = new File("hmacs");
        if (!digests.exists()) {
            digests.mkdir();
        }

        for (var f : folder.listFiles()) {
            File out = new File("hmacs\\" + f.getName().substring(0, f.getName().length() - 3) + "hmac");
            if (out.exists()) {
                continue;
            }
            try (var fos = new FileWriter(out
            )) {
                var mac = getMAC(f.getPath(), secretKey);

                fos.write(Base64.getEncoder().encodeToString(mac));
            }
        }
    }

    public static byte[] toByteArray(String hexString) {
        if (hexString.length() % 2 != 0) {
            throw new RuntimeException("The hex string must have a size multiple of 2");
        }
        byte[] result = new byte[hexString.length() / 2];
        for (int i = 0; i < result.length; i++) {
            String currentPair = hexString.substring(i * 2, (i + 1) * 2);
            result[i] = (byte) Integer.parseInt(currentPair.toUpperCase(), 16);
        }
        return result;
    }

    // Step 3: Decrypt and verify the document
    public static boolean retrieveAndVerifyDocument(String file, String hashFile, String hmacFile, String secretKey) throws Exception {
        // Verify HMAC and digest for the given file
        // Return true if the files has not been changed
        try (var fis = new FileInputStream(file); var hash = new BufferedReader(new FileReader(hashFile))) {
            var hashArr = toByteArray(hash.readLine());
            MessageDigest md = MessageDigest.getInstance("MD5");
            var digest = md.digest(fis.readAllBytes());
            if (!Arrays.equals(digest, hashArr)) {
                return false;
            }
        }

        try (var hmac = new BufferedReader(new FileReader(hmacFile))) {

            var mac = getMAC(file, secretKey);
            if (!hmac.readLine().equals(Base64.getEncoder().encodeToString(mac))) {
                return false;
            }
        }

        return true;
    }

    // Step 4: Generate AES key from the shared secret. See Excel for details
    public static byte[] generateSecretKey(String sharedSecret) throws Exception {
        var arr = sharedSecret.getBytes();
        byte mask = 1 << 4;
        arr[6] = (byte) ((arr[6] & 0xff) ^ mask);
        return arr;
    }


    // Step 5: Encrypt document with AES and received key
    public static void encryptDocument(String filePath, byte[] key) throws Exception {
        var outPath = filePath.substring(9, filePath.length() - 3);
        encrypt(filePath, key, AES_ALGORITHM, outPath + "enc");
    }

    public static void encrypt(
            String inputFileName,
            byte[] key,
            String algorithm,
            String outputFileName) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        File inputFile = new File(inputFileName);
        if (!inputFile.exists())
            throw new RuntimeException("**** NO FILE *****");
        File outputFile = new File(outputFileName);
        if (!outputFile.exists())
            outputFile.createNewFile();

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outputFile);

        //create the Cipher
        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        SecretKeySpec secretkey = new SecretKeySpec(key, algorithm);

        //init the cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretkey);

        byte[] block = new byte[cipher.getBlockSize()];

        while (true) {
            int noBytes = fis.read(block);
            if (noBytes == -1)
                break;
            byte[] cipherBlock = cipher.update(block, 0, noBytes);
            fos.write(cipherBlock);
        }

        //IMPORTANT - get the last cipher block
        byte[] cipherBlock = cipher.doFinal();
        fos.write(cipherBlock);

        fis.close();
        fos.close();

    }

    public static void main(String[] args) {


        try {
            // Step 1: Generate and store file digest
            generateFilesDigest(FOLDER_PATH);

            // Step 2: Generate and store HMAC for file authentication
            generateFilesHMAC(FOLDER_PATH, SHARED_SECRET);

            String filename = "messages/message_1_2qcqxj.txt"; //choose any message.txt file from the folder and test it
            String hashFile = "digests/message_1_2qcqxj.digest"; //the corresponding hash file
            String hmacFile = "hmacs/message_1_2qcqxj.hmac"; //the corresponding hmac file

            // Step 3: Verify the document
            if (retrieveAndVerifyDocument(filename, hashFile, hmacFile, SHARED_SECRET)) {
                System.out.println("Document retrieved successfully. Integrity verified.");
            } else {
                System.out.println("Document verification failed!");
            }

            //Step 3: Change the file content and re-check it to be sure your solution is correct


            // Step 4: Get the derived key
            byte[] derivedKey = generateSecretKey(SHARED_SECRET);

            // Step 5: Encrypt the document
            encryptDocument(filename, derivedKey);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}