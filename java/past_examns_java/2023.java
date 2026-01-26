import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Main {
    public static byte[] generateDigitalSignature(
            String fileName, PrivateKey privKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        File file = new File(fileName);
        if (!file.exists())
            throw new RuntimeException("*** NO File ***");
        FileInputStream fis = new FileInputStream(file);

        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privKey);

        byte[] buffer = fis.readAllBytes();
        fis.close();

        signature.update(buffer);
        return signature.sign();
    }

    public static KeyStore getKeyStore(
            String ksFileName, String ksPass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        File ksFile = new File(ksFileName);
        if (!ksFile.exists())
            throw new RuntimeException("NO KS file !!!");
        FileInputStream fis = new FileInputStream(ksFile);

        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(fis, ksPass.toCharArray());

        fis.close();

        return ks;
    }

    public static PrivateKey getPrivateKey(
            KeyStore ks,
            String alias, String aliasPass) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {

        if (ks == null || !ks.containsAlias(alias))
            throw new RuntimeException("*** NO KS or alias ***");

        //In production don't - use the private key inside the HSM
        PrivateKey pk = (PrivateKey) ks.getKey(alias, aliasPass.toCharArray());
        return pk;

    }

    public static void decrypt(
            String inputFileName,
            byte[] key,
            String algorithm,
            String outputFileName) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        File inputFile = new File(inputFileName);
        if (!inputFile.exists())
            throw new RuntimeException("**** NO FILE *****");
        File outputFile = new File(outputFileName);
        if (!outputFile.exists())
            outputFile.createNewFile();

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outputFile);


        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/NoPadding");

        //get the IV from the file - is the 1st block
        byte[] IV = new byte[cipher.getBlockSize()];
        IV[10] = (byte) 0xff;
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, algorithm),
                ivSpec);

        byte[] block = new byte[cipher.getBlockSize()];
        while (true) {
            int noBytes = fis.read(block);
            if (noBytes == -1)
                break;
            byte[] cipherBlock = cipher.update(block, 0, noBytes);
            fos.write(cipherBlock);
        }
        byte[] cipherBlock = cipher.doFinal();
        fos.write(cipherBlock);
        fos.close();
        fis.close();

    }

    public static byte[] getPBKDFValue(
            String password,
            String salt,
            int noIterations,
            int outputNoOfBits,
            String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec pbkdfSpec = new PBEKeySpec(
                password.toCharArray(),
                salt.getBytes(),
                noIterations,
                outputNoOfBits);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
        byte[] result = keyFactory.generateSecret(pbkdfSpec).getEncoded();
        return result;

    }

    public static PublicKey getPublicKeyFromX509Certificate(String certFileName) throws CertificateException, IOException {
        File certFile = new File(certFileName);
        if (!certFile.exists())
            throw new RuntimeException("*** NO X509 certificate file ***");
        FileInputStream fis = new FileInputStream(certFile);

        CertificateFactory certFactory =
                CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);

        fis.close();

        return certificate.getPublicKey();

    }

    public static boolean validateSignature(
            String fileName,
            byte[] digitalSignature,
            PublicKey pubKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {

        File file = new File(fileName);
        if (!file.exists())
            throw new RuntimeException("*** NO File ***");
        FileInputStream fis = new FileInputStream(file);

        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(pubKey);

        byte[] buffer = fis.readAllBytes();
        fis.close();

        signature.update(buffer);

        return signature.verify(digitalSignature);
    }

    public static void main(String[] args) throws Exception {
        String baseHash = "heLCZjtE3iWRFodKzkYBYS7OThA+5b9G3XfNqV/rTyo=";

        File folder = new File("users2");

        var filePath = "";

        for (var f : folder.listFiles()) {
            try (var fis = new FileInputStream(f.getPath())) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                var digest = md.digest(fis.readAllBytes());
                if (baseHash.equals(Base64.getEncoder().encodeToString(digest))) {
                    filePath = f.getPath();
                    break;
                }
            }
        }
        System.out.println(filePath);

        decrypt(filePath, "userfilepass%3%5".getBytes(), "AES", "password.txt");
        try (BufferedReader bf = new BufferedReader(new FileReader("password.txt")); FileOutputStream fos =
                new FileOutputStream("andrei.enc")) {
            String password = bf.readLine();
            System.out.println(password);

            password += "ism2021";

            var saltedPass = getPBKDFValue(password, "ism2021", 150, 20 * 8, "PBKDF2WithHmacSHA1");
            fos.write(saltedPass);

            KeyStore ks = getKeyStore("ismkeystore.ks", "passks");
            PrivateKey ismKey1Priv =
                    getPrivateKey(ks, "ismkey1", "passks");

            var sig = generateDigitalSignature("andrei.enc", ismKey1Priv);
            try (OutputStream os = new FileOutputStream("signature.sig")) {
                os.write(sig);
            }

            var pubKey = getPublicKeyFromX509Certificate("ISMCertificateX509.cer");
            var bool = validateSignature("andrei.enc", sig, pubKey);
            if (bool) {
                System.out.println("Valid sig");
            } else {
                System.out.println("Invalid sig");
            }

        }


    }
}