import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class RSAFileEncryption {

    private static final Logger logger = LogManager.getLogger(RSAFileEncryption.class);

    private BigInteger n;       // Modulo
    private BigInteger e;       // Esponente pubblico
    private BigInteger d;       // Esponente privato
    private int bitLength = 1024; // Lunghezza della chiave in bit
    private SecureRandom random;  // Numero randomico

    public RSAFileEncryption() {
        random = new SecureRandom();
        generateKeys();
        logger.info("Chiavi generate con successo.");
    }

    private void generateKeys() {
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        e = BigInteger.probablePrime(bitLength / 2, random);
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
            e = e.add(BigInteger.ONE);
        }
        d = e.modInverse(phi);
        logger.debug("Modulo n: " + n + ", Esponente pubblico e: " + e + ", Esponente privato d: " + d);
    }

    public BigInteger encrypt(BigInteger message) {
        logger.info("Cifratura del messaggio...");
        return message.modPow(e, n);
    }

    public BigInteger decrypt(BigInteger encrypted) {
        logger.info("Decifratura del messaggio...");
        return encrypted.modPow(d, n);
    }

    public void encryptFile(String inputFilePath, String outputFilePath) throws IOException {
        logger.info("Cifratura del file: " + inputFilePath);
        byte[] fileData = Files.readAllBytes(Paths.get(inputFilePath));
        BigInteger fileAsInt = new BigInteger(fileData);
        BigInteger encryptedData = encrypt(fileAsInt);

        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(encryptedData.toByteArray());
        }
        logger.info("File cifrato salvato in: " + outputFilePath);
    }

    public void decryptFile(String inputFilePath, String outputFilePath) throws IOException {
        logger.info("Decifratura del file: " + inputFilePath);
        byte[] encryptedData = Files.readAllBytes(Paths.get(inputFilePath));
        BigInteger encryptedAsInt = new BigInteger(encryptedData);
        BigInteger decryptedData = decrypt(encryptedAsInt);

        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(decryptedData.toByteArray());
        }
        logger.info("File decifrato salvato in: " + outputFilePath);
    }

    public static void main(String[] args) {
        try {
            RSAFileEncryption rsa = new RSAFileEncryption();
            String inputFile = "src/main/resources/fileDaCriptare.txt";
            String encryptedFile = "fileCriptato.txt";
            String decryptedFile = "fileDecriptato.txt";

            rsa.encryptFile(inputFile, encryptedFile);
            rsa.decryptFile(encryptedFile, decryptedFile);

        } catch (Exception e) {
            logger.error("Si è verificato un errore: ", e);
        }
    }
}
