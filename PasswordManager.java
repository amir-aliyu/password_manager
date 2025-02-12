import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {

    public void createFile(String filename) {
        try {
            File file = new File(filename);
            Scanner s = new Scanner(System.in);
            if (file.createNewFile()) {
                FileWriter writeToFile = new FileWriter("./" + filename);
                System.out.print("Please enter an initial password:");
                // create a key 
                String keyString = s.nextLine();
                System.out.print("File created: " + file.getName());
                writeToFile.write("password: "+ keyString);
                writeToFile.close();
            } else {
                System.out.print("Please input the password to access the file:");
                String keyString = s.nextLine();
            }
        } catch (IOException e) {
            System.out.println("File error.");
        }
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

    public void encrypt(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException { 
        
        SecretKeySpec key = getSecretKeySpec();
        // actually encrypt it 
        createFile("test.txt");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedData = cipher.doFinal(message.getBytes());
        String messageString = new String(Base64.getEncoder().encode(encryptedData));
        System.out.println(messageString);

    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {

        PasswordManager manager = new PasswordManager();
        Scanner scanner = new Scanner(System.in);

        System.out.print("Do you want to encrypt or decrypt (e|d): ");
        String option = scanner.nextLine();
        
        if (option.equals("d")) {
            System.out.print("Enter message to decrypt: ");
        } else if (option.equals("e")) {
            System.out.print("Enter message to encrypt: ");
            manager.encrypt(scanner.nextLine());
        } else {
            System.err.print("Invalid option");
            System.exit(1);
        }

    }
}
