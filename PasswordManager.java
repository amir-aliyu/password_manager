import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {

    public void createFile(String filename) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, IOException {
            File file = new File("./" + filename);
            Scanner s = new Scanner(System.in);
            if (!file.exists()){ 
                file.createNewFile(); 
                FileWriter writeToFile = new FileWriter(file);
                System.out.print("Please enter an initial password:");
                // create a key 
                String plaintextPassword = s.nextLine();
                // encrypt the key string 
                String encryptedMessage = encrypt(plaintextPassword);
                System.out.print("File created: " + file.getName());
                String saltString = "1B9Wx/oPXyg5ufgmV/lLoQ==";
                writeToFile.write(saltString + ":" + encryptedMessage);
                writeToFile.close();
           
            } else {
                System.out.print("Please enter the password to access the file:");
                // create a key 
                String plaintextPassword = s.nextLine();
                // encrypt the key string
                String[] passwords = new String[3];
                Scanner scanFile = new Scanner(file);
                while(scanFile.hasNext()) {
                    passwords = scanFile.nextLine().split(":");
                    System.out.println("first: "+ passwords[0]);
                    System.out.println("second: "+ passwords[1]);
                    
                }
            String saltString = passwords[0];
                    String encryptedFilePassword = passwords[1];
                
                
                // String encryptedMessage = encrypt(plaintextPassword);
                // String saltString = "1B9Wx/oPXyg5ufgmV/lLoQ==";
         
                SecretKeySpec key = getSecretKeySpec();
                
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, key);

                byte[] salt = Base64.getDecoder().decode(saltString.getBytes());

                KeySpec spec = new PBEKeySpec(plaintextPassword.toCharArray(), salt, 1024, 128);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                SecretKey privateKey = factory.generateSecret(spec);
                
                byte [] encryptedData = Base64.getDecoder().decode(encryptedFilePassword);
                byte [] decryptedData = cipher.doFinal(encryptedData);
                // String decryptedMessage = new String(decryptedData);
               String decryptedMessage = new String(decryptedData);
                System.out.println("Decrypted message: " + decryptedMessage); 
                // System.out.println("Message is " + decryptedMessage);

                if (decryptedMessage.equals(plaintextPassword)) {
                    System.out.println(plaintextPassword + " matches "+ decryptedMessage);
                } else {
                    System.out.println("incorrect password");
                }

//                 writeToFile.write(keyString + ":" + encryptedMessage);



            }
            // s.close();
    }

    public SecretKeySpec getSecretKeySpec() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltString = "1B9Wx/oPXyg5ufgmV/lLoQ==";
        salt = Base64.getDecoder().decode(saltString.getBytes());

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password: ");
        String keyString = scanner.nextLine();

        // salt, num iterations, key size
        PBEKeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 1024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey privateKey = factory.generateSecret(spec);

        // get bytes from key i just generated
        SecretKeySpec key = new SecretKeySpec(privateKey.getEncoded(), "AES");
        
        return key;

    }

    public SecretKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltString = "1B9Wx/oPXyg5ufgmV/lLoQ==";
        salt = Base64.getDecoder().decode(saltString.getBytes());

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password: ");
        String keyString = scanner.nextLine();

        // salt, num iterations, key size
        PBEKeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 1024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey privateKey = factory.generateSecret(spec);
        
        return privateKey; 
    }

    public String encrypt(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, IOException { 
        
        SecretKeySpec key = getSecretKeySpec();
        // actually encrypt it 
        // createFile("test.txt");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedData = cipher.doFinal(message.getBytes());
        String messageString = new String(Base64.getEncoder().encode(encryptedData));
        return messageString;

    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {

        PasswordManager manager = new PasswordManager();
        Scanner scanner = new Scanner(System.in);

        manager.createFile("hey.txt");

        System.out.print("Do you want to encrypt or decrypt (e|d): ");
        String option = scanner.nextLine();
        
        if (option.equals("d")) {
            System.out.print("Enter message to decrypt: ");
        } else if (option.equals("e")) {
            System.out.print("Enter message to encrypt: ");
            // manager.encrypt(scanner.nextLine());
        } else {
            System.err.print("Invalid option");
            System.exit(1);
        }

        scanner.close();
    }
}
