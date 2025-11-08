package day01;

import java.util.Arrays;

public class TestBitwise {
    public static void main(String[] args) {
        byte binaryValue = (byte) 0b10001111;
        binaryValue = (byte) 0x8F;
        binaryValue = (byte) (1 << 7 | 1 << 3 | 1 << 2 | 1 << 1 | 1);
        System.out.println(Integer.toBinaryString(binaryValue & 0xFF));

        byte value = 8;
        var r = (byte) (value >> 1); // divide by 2
        System.out.println(r);
        byte result = (byte) (value >> 3); // divide by 8
        System.out.println(result);


        byte byteValue = 0b00010011;
        result = (byte) (byteValue >> 1);
        System.out.println(result);
        byteValue = (byte) 0b11110010;

        System.out.println(byteValue);
        result = (byte) (byteValue >> 1);
        System.out.println(result); // you get 11111001
        result = (byte) ((0xFF & byteValue) >>> 1); //
        System.out.println(Integer.toBinaryString(result));

        byte[] key1 = {(byte) 0xFA, 0x13, 0x14};
        byte[] key2 = {(byte) 0xFA, 0x13, 0x14};

        System.out.println(Arrays.equals(key1, key2));

        // checking the value of a particular bit in a byte;
        byteValue = (byte) 0b10011101;

        // we count bits from right
        // we start from one
        // check if the 5th bit is 1 or 0
        int bitPosition = 2;
        byte mask = (byte) (1 << (bitPosition - 1));
        System.out.println(Integer.toBinaryString(mask & 0xFF));
        boolean isBitSet = (byteValue & mask) != 0;
        System.out.println("is bit " + bitPosition + " set? " + isBitSet);


    }
}
