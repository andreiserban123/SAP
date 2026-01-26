import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;

public class Main {

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


        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");

        //get the IV from the file - is the 1st block
        byte[] IV = new byte[cipher.getBlockSize()];
        IV[15] = 23;
        IV[14] = 20;
        IV[13] = 2;
        IV[12] = 3;

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

    public static void main(String[] args) throws Exception {

        File folder = new File("system32");

        var map = new HashMap<String, String>();

        try (var br = new BufferedReader(new FileReader("sha2Fingerprints.txt"))) {
            while (br.ready()) {
                var path = br.readLine();
                var hash = br.readLine();
                map.put(path, hash);
            }
        }
        String path = "";
        byte[] password = null;
        for (var f : folder.listFiles()) {
            try (var fis = new FileInputStream(f.getPath())) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                password = fis.readAllBytes();
                byte[] digest = md.digest(password);
                var b64 = Base64.getEncoder().encodeToString(digest);
                if (!map.get(f.getPath()).equals(b64)) {
                    path = f.getPath();
                    break;
                }
            }
        }

        System.out.println(path);

        decrypt("financialdata.enc", password, "AES", "financialdata.txt");
        KeyStore ks = getKeyStore("ismkeystore.ks", "passks");
        var priv = getPrivateKey(ks, "ismkey1", "passks");

        try (FileWriter fw = new FileWriter("myresponse.txt"); BufferedReader br = new BufferedReader(new FileReader("financialdata.txt"))) {
            var line = br.readLine();
            fw.write(line);
        }


        var sign = generateDigitalSignature("myresponse.txt", priv);
        try (var ous = new FileOutputStream("DataSignature.ds")) {
            ous.write(sign);
        }

        System.out.println(validateSignature("myresponse.txt", sign, getPublicKey(ks, "ismkey1")));
    }

    public static PublicKey getPublicKey(KeyStore ks, String alias) throws KeyStoreException {
        if (ks == null || !ks.containsAlias(alias))
            throw new RuntimeException("*** Missing KS or alias ***");

        PublicKey publicKey =
                (PublicKey) ks.getCertificate(alias).getPublicKey();
        return publicKey;
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

    public static boolean validateSignature(
            String fileName,
            byte[] digitalSignature,
            PublicKey pubKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {

        File file = new File(fileName);
        if (!file.exists())
            throw new RuntimeException("*** NO File ***");
        FileInputStream fis = new FileInputStream(file);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(pubKey);

        byte[] buffer = fis.readAllBytes();
        fis.close();

        signature.update(buffer);

        return signature.verify(digitalSignature);
    }

    public static byte[] generateDigitalSignature(
            String fileName, PrivateKey privKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        File file = new File(fileName);
        if (!file.exists())
            throw new RuntimeException("*** NO File ***");
        FileInputStream fis = new FileInputStream(file);

        Signature signature = Signature.getInstance("SHA256withRSA");
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
}