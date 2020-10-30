//encryption and then AONT in serial
package aont0;
import aont0.aes_gcm;
import aont0.CryptoUtils;

import java.io.File;
import java.nio.file.Files;
import javax.crypto.SecretKey;

public class aont {
	
	public static void main(String[] args) throws Exception{
		long startTime = System.nanoTime();
		String filePath = "/home/yeeman/Documents/100MB.txt";
		
		// encrypt and decrypt need the same key.
        // get AES 256 bits (32 bytes) key
        SecretKey secretKey = CryptoUtils.getAESKey(256);

        // encrypt and decrypt need the same IV.
        // AES-GCM needs IV 96-bit (12 bytes)
        byte[] iv = CryptoUtils.getRandomNonce(12);
        
		File file = new File(filePath);
		byte[] inputArray = Files.readAllBytes(file.toPath());
	
		//apply Bastion AONT to inputArray
		int t = 0;
		for (int i=0; i<inputArray.length; i++) {
			t=t^inputArray[i];
		}
			
		byte[] inputArrayAONT = new byte[inputArray.length]; 
		for (int i=0; i<inputArray.length; i++) {
			inputArrayAONT[i]=(byte)(inputArray[i]^t);
		}
			
		//encrypt inputArrayAONT with aes 
		byte[] encryptedArray = new byte[inputArray.length];
		encryptedArray = aes_gcm.encryptWithPrefixIV(inputArrayAONT, secretKey, iv);
		
		System.out.println("Length of encryptedArray: "+encryptedArray.length);		
		long endTime = System.nanoTime();
		System.out.println("Took "+(endTime - startTime) + " ns"); 
		
	}


}
