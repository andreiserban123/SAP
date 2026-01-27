package ro.ase.ism.sap;

import java.util.Base64;

public class Utility {
	public static String toHexString(byte[] input) {
		StringBuilder sb = new StringBuilder();
		for(byte value : input) {
			sb.append(String.format("%02X", value));
		}
		return sb.toString();
	}
	
	public static String toBase64(byte[] input) {
		return Base64.getEncoder().encodeToString(input);
	}
	
	public static byte[] fromBase64(String input) {
		return Base64.getDecoder().decode(input);
	}

		static byte rotateLeft(byte b, int n) {
			int x = b & 0xFF;      
			n = n & 7;             
			return (byte)(((x << n) & 0xFF) | (x >>> (8 - n)));
		}


		static byte rotateRight(byte b, int n) {
			int x = b & 0xFF;
			n = n & 7;
			return (byte)((x >>> n) | ((x << (8 - n)) & 0xFF));
		}

}










