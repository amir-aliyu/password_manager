import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
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
    String plaintextPassword;
    SecretKeySpec key = null;

    public File createFile(String filename) throws Exception {
            File file = new File("./" + filename);
            FileWriter writeToFile = null;
            Scanner s = new Scanner(System.in);
            // SecretKeySpec key = null;

            // ENCRYPT
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            // String saltString = "1B9Wx/oPXyg5ufgmV/lLoQ==";
            // salt = Base64.getDecoder().decode(saltString.getBytes());
    
            if (!file.exists()){ 
                file.createNewFile(); 
                writeToFile = new FileWriter(file, true);
                System.out.print("Please enter an initial password:");
                // create a key 
                plaintextPassword = s.nextLine();
                // encrypt the key string 
                // salt, num iterations, key size
                // Store generated salt in file
                String saltString = Base64.getEncoder().encodeToString(salt); // Save the generated salt
                System.out.println("generated salt string: "+ saltString);
                key = generateAESKey(plaintextPassword, salt);
                System.out.println("Encryption Key: " + Base64.getEncoder().encodeToString(key.getEncoded()));
        
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, key);
       
                // to encrypt, get bytes
                byte[] encryptedData = cipher.doFinal(plaintextPassword.getBytes());
                String messageString = new String(Base64.getEncoder().encode(encryptedData));
                System.out.println("Encryption Key: " + Base64.getEncoder().encodeToString(key.getEncoded()));

                // String encryptedMessage = encrypt(plaintextPassword);

                System.out.print("File created: " + file.getName());
                writeToFile.write(saltString + ":" + messageString);
                writeToFile.close();
           
            } else {
                writeToFile = new FileWriter(file, true);
                System.out.print("Please enter the password to access the file:");
                // create a key 
                plaintextPassword = s.nextLine();

                BufferedReader br = new BufferedReader(new FileReader(file));
                StringBuilder sb = new StringBuilder();
                String line = br.readLine();
            
                while (line != null) {
                    sb.append(line);
                    sb.append(System.lineSeparator());
                    line = br.readLine();
                }
                String everything = sb.toString();
                System.out.println("everything: "+everything);
                String[] pairs = everything.split("[:\\n]");
                for (String pair : pairs) {
                    pair = pair.trim();
                    System.out.println("pair: "+ pair);
                }
                
                String saltyString = pairs[0];
                // byte[] decodedSalt = Base64.getDecoder().decode(saltyString);
                String encryptedFilePassword = pairs[1];   
                System.out.println("FINAL salt: "+ saltyString);
                
                byte[] decodedSalt = Base64.getDecoder().decode(saltyString);
                key = generateAESKey(plaintextPassword, decodedSalt);
                
                Cipher cipher = Cipher.getInstance("AES");  
                cipher.init(Cipher.DECRYPT_MODE, key);

                byte [] encryptedData = Base64.getDecoder().decode(encryptedFilePassword);
                byte [] decryptedData = cipher.doFinal(encryptedData); // decrypt the mf data
                String decryptedMessage = new String(decryptedData);
                System.out.println("Decrypted message: " + decryptedMessage); 

                if (decryptedMessage.equals(plaintextPassword)) {
                    System.out.println(plaintextPassword + " matches "+ decryptedMessage);
                } else {
                    System.out.println("incorrect password");
                }

            }
            return file;
            // s.close();
    }

    private SecretKeySpec generateAESKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey secret = factory.generateSecret(spec);
        
        return new SecretKeySpec(secret.getEncoded(), "AES");
    }


    public void storePassword(File file) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
        Scanner s = new Scanner(System.in);
        System.out.print("Enter label for password: ");
        String label= s.nextLine();
        System.out.print("Enter password to store: ");
        String password = s.nextLine();
       
        String saltString = "1B9Wx/oPXyg5ufgmV/lLoQ==";
        byte[] salt = Base64.getDecoder().decode(saltString);

        // PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1024, 128);
        // SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // SecretKey privateKey = factory.generateSecret(spec);

        // SecretKeySpec key = new SecretKeySpec(privateKey.getEncoded(), "AES");        
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedData = cipher.doFinal(password.getBytes());
        String encryptedPassword = new String(Base64.getEncoder().encode(encryptedData));
        
        FileWriter writeToFile = new FileWriter(file, true);
        writeToFile.write("\n" + label + ":" + encryptedPassword);
        writeToFile.close();

    }

    public void readPassword(File file) throws Exception {
        Scanner s = new Scanner(System.in);
        System.out.print("Enter label for password: ");
        String label= s.nextLine();
        
        BufferedReader br = new BufferedReader(new FileReader(file));
        StringBuilder sb = new StringBuilder();
        String line = br.readLine();
    
        while (line != null) {
            sb.append(line);
            sb.append(System.lineSeparator());
            line = br.readLine();
        }
        String encryptedPassword = null;
        String everything = sb.toString();
        System.out.println("everything: "+everything);
        String[] pairs = everything.split("[:\\n]");
        for (int i = 0; i < pairs.length; i++) {
            pairs[i] = pairs[i].trim();
            if (pairs[i].equals(label)) {
                encryptedPassword = pairs[i+1];
                System.out.println("Found: "+ pairs[i+1]);
            }
        }
        if (encryptedPassword == null) {
            System.err.println("No password found for that label");
        } 

        // String saltyString = pairs[0];
        // byte[] decodedSalt = Base64.getDecoder().decode(saltyString);
        // System.out.println("FINAL salt: "+ saltyString);
        
        // byte[] decodedSalt = Base64.getDecoder().decode(saltyString);
        System.out.println("plaintext password: "+plaintextPassword);
        // SecretKeySpec key = generateAESKey(plaintextPassword, decodedSalt);
        
        Cipher cipher = Cipher.getInstance("AES");  
        cipher.init(Cipher.DECRYPT_MODE, key);
        System.out.println("encrypted password: "+encryptedPassword);
        byte [] encryptedData = Base64.getDecoder().decode(encryptedPassword);
        byte [] decryptedData = cipher.doFinal(encryptedData); // decrypt the mf data
        String decryptedMessage = new String(decryptedData);
        System.out.println("Decrypted message: " + decryptedMessage); 

        // decrypt encryptedPassword 



    }


    public static void main(String[] args) throws Exception {

        PasswordManager manager = new PasswordManager();
        Scanner scanner = new Scanner(System.in);
        File file = manager.createFile("passwords.txt");


        System.out.print("Do you want to add a password, read a password, or quit? (a|r|q): ");
        String option = scanner.nextLine();
         
        if (option.equals("a")) {
            manager.storePassword(file);
        
        } else if (option.equals("r")) {
            manager.readPassword(file);
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
