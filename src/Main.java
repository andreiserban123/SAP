import java.util.Arrays;

class Main {

    public static String toHexString(byte[] values) {
        StringBuilder sb = new StringBuilder();
        for (byte value : values) {
            sb.append(String.format("%02x", value));
        }
        return sb.toString();
    }

    public static byte[] toByteArray(String hexString) {

        System.out.println("You entered this hexString: " + hexString);
        if (hexString.length() % 2 != 0) {
            throw new RuntimeException("Hex string's length must be even");
        }

        byte[] result = new byte[hexString.length() / 2];
        for (int i = 0; i < result.length; i++) {
            String currentPair = hexString.substring(2 * i, 2 * (i + 1));
            result[i] = (byte) Integer.parseInt(currentPair, 16);
        }
        return result;
    }

    public static void main(String[] args) {
        System.out.println("strings");
        String hash1 = "FA23D4";
        String hash2 = "FA23D4";
        System.out.println(hash2.equals(hash1));
        hash1 = new String("FA234D4");
        hash2 = "FA234D4";

        System.out.println(hash2 == hash1);

        System.out.println("Integers");
        // small integers are managed by a constant integers pools
        Integer vb1 = 100000;
        Integer vb2 = 100000;
        // use equals
        System.out.println(vb1 == vb2);
        System.out.println(vb1.equals(vb2));

        System.out.println("hex");

        //hex strings

        byte byteValue = 23;
        byteValue = 0x17; // 23 in hex
        //
//        System.out.printf("%x\n", byteValue);
//        System.out.println(byteValue);
//        byteValue  = 10;
//        System.out.println(String.format("%02x", byteValue));

        byte[] values = {0x23, 0xb, 0x12, 0x4};
        String valuesHex = toHexString(values).toUpperCase();
        System.out.println(valuesHex);
        // restore values from hex
        String password = "password";

        byte[] passAsByteArray = password.getBytes();
        String hexPassword = toHexString(passAsByteArray);
        System.out.println(hexPassword);
        System.out.println(passAsByteArray.length);

        byte[] binaryPassword = {0x30, 0x39, 0x00, 0x05};
        byte[] binaryPassword2 = {0x30, 0x39, 0x00, 0x06};
        password = new String(binaryPassword);
        System.out.println(password);
        password = new String(binaryPassword2);
        System.out.println(password);

        // convert hex strings to values or byte array
        String anotherHexValue = "23";


        var byteArr = toByteArray(hexPassword);
        System.out.println(Arrays.toString(byteArr));

    }
}