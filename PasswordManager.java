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

    int ADD_FLAG = 0;
    int READ_FLAG = 0;

    public File createFile(String filename) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, IOException {
            File file = new File("./" + filename);
            FileWriter writeToFile = null;
            Scanner s = new Scanner(System.in);

            // ENCRYPT
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            String saltString = "1B9Wx/oPXyg5ufgmV/lLoQ==";
            salt = Base64.getDecoder().decode(saltString.getBytes());
    
            if (!file.exists()){ 
                file.createNewFile(); 
                writeToFile = new FileWriter(file, true);
                System.out.print("Please enter an initial password:");
                // create a key 
                String plaintextPassword = s.nextLine();
                // encrypt the key string 
                // salt, num iterations, key size
                PBEKeySpec spec = new PBEKeySpec(plaintextPassword.toCharArray(), salt, 1024, 128);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                SecretKey privateKey = factory.generateSecret(spec);
        
                // get bytes from key i just generated
                SecretKeySpec key = new SecretKeySpec(privateKey.getEncoded(), "AES");        
                // actually encrypt it 
                // createFile("test.txt");
        
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, key);
        
                byte[] encryptedData = cipher.doFinal(plaintextPassword.getBytes());
                String messageString = new String(Base64.getEncoder().encode(encryptedData));

                // String encryptedMessage = encrypt(plaintextPassword);

                System.out.print("File created: " + file.getName());
                writeToFile.write(saltString + ":" + messageString);
                writeToFile.close();
           
            } else {
                writeToFile = new FileWriter(file, true);
                System.out.print("Please enter the password to access the file:");
                // create a key 
                String plaintextPassword = s.nextLine();
                // encrypt the key string
                String[] passwords = new String[50];
                Scanner scanFile = new Scanner(file);
                while(scanFile.hasNext()) {
                    passwords = scanFile.nextLine().split(":");
                    System.out.println("first: "+ passwords[0]);
                    System.out.println("length: "+ passwords[0].length());
                    System.out.println("second: "+ passwords[1]);
                }
                String finalString = passwords[0];
                System.out.println("final string: "+finalString);

                for(int i = 0; i < passwords.length; i++) {
                    System.out.println("index: "+ i + " word: "+ passwords[i]);
                }

                String saltyString = passwords[1];
                byte[] decodedSalt = Base64.getDecoder().decode(saltyString);
                String encryptedFilePassword = passwords[0];   
                System.out.println("FINAL salt: "+ saltyString);
                
                KeySpec spec = new PBEKeySpec(plaintextPassword.toCharArray(), decodedSalt, 1024, 128);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                SecretKey privateKey = factory.generateSecret(spec);
                SecretKeySpec key = new SecretKeySpec(privateKey.getEncoded(), "AES");
                Cipher cipher = Cipher.getInstance("AES");  
                cipher.init(Cipher.DECRYPT_MODE, key);
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

            }
            return file;
            // s.close();
    }

    public void storePassword(File file) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
        Scanner s = new Scanner(System.in);
        System.out.print("Enter label for password: ");
        String label= s.nextLine();
        System.out.print("Enter password to store: ");
        String password = s.nextLine();
       
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltString = "1B9Wx/oPXyg5ufgmV/lLoQ==";
        salt = Base64.getDecoder().decode(saltString.getBytes());

        // salt, num iterations, key size
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey privateKey = factory.generateSecret(spec);

        // get bytes from key i just generated
        SecretKeySpec key = new SecretKeySpec(privateKey.getEncoded(), "AES");        
        // actually encrypt it 
        // createFile("test.txt");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedData = cipher.doFinal(password.getBytes());
        String encryptedPassword = new String(Base64.getEncoder().encode(encryptedData));
        
        FileWriter writeToFile = new FileWriter(file, true);
        writeToFile.write("\n" + label + ":" + encryptedPassword);
        writeToFile.close();

    }


    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {

        PasswordManager manager = new PasswordManager();
        Scanner scanner = new Scanner(System.in);
        File file = manager.createFile("passwords.txt");


        System.out.print("Do you want to add a password, read a password, or quit? (a|r|q): ");
        String option = scanner.nextLine();
         
        if (option.equals("a")) {
            manager.storePassword(file);
        
        } else if (option.equals("r")) {
            System.out.print("Enter label for password: ");
            // manager.encrypt(scanner.nextLine());
        } else if (option.equals("q")) {
            System.exit(0);
        } else {
            System.err.print("Invalid option");
            System.exit(1);
        }

        scanner.close();
    }
}
