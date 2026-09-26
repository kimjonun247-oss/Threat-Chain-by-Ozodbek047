import javax.crypto.Cipher;
public class WeakCrypto { Cipher c() throws Exception { return Cipher.getInstance("DES/ECB/PKCS5Padding"); } }
