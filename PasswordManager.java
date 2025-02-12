import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {
    
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {

        // generate a salt 
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; 
        random.nextBytes(salt);
        //String saltString = Base64.getEncoder().encodeToString(salt);
        String saltString = "1B9Wx/oPXyg5ufgmV/lLoQ==";
        salt = Base64.getDecoder().decode(saltString.getBytes());

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password: ");
        String keyString = scanner.nextLine();

        // salt, num iterations, key size 
        PBEKeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 1024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey privateKey = factory.generateSecret(spec); 

        System.out.print("Do you want to encrypt or decrypt (e|d): ");
        String option = scanner.nextLine();
        Cipher cipher = Cipher.getInstance("AES");
        // get bytes from key i just generated 
        SecretKeySpec key = new SecretKeySpec(privateKey.getEncoded(), "AES");

        if (option.equals("d")) {
            System.out.print("Enter message to decrypt: ");
        } 
        else if (option.equals("e")) {
            System.out.print("Enter message to encrypt: ");
            String message = scanner.nextLine();
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encryptedData = cipher.doFinal(message.getBytes());
            String messageString = new String(Base64.getEncoder().encode(encryptedData));
            System.out.println(messageString);
            
        } 
        else {
            System.err.print("Invalid option");
            System.exit(1);
        }

    } 
}

