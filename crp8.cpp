import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
public class Blowfish1 
{
 public static void main(String[] args) 
{
 try 
{
 String plaintext = "Hello, World!";
 KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
 keyGen.init(128); // Key size: 128 bits
 SecretKey secretKey = keyGen.generateKey();            
String encryptedText = encrypt(plaintext, secretKey);  
System.out.println("Encrypted Text: " + encryptedText);
String decryptedText = decrypt(encryptedText, secretKey);
System.out.println("Decrypted Text: " + decryptedText);
 }
catch (Exception e) 
{
 e.printStackTrace();
 }
 }
 public static String encrypt(String plaintext, SecretKey secretKey) throws Exception {
Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
 cipher.init(Cipher.ENCRYPT_MODE, secretKey);
 byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
 return Base64.getEncoder().encodeToString(encryptedBytes);
 }
public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception 
{
Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
cipher.init(Cipher.DECRYPT_MODE, secretKey);
 byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
 return new String(decryptedBytes);
}
}

