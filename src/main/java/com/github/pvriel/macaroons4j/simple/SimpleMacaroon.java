package com.github.pvriel.macaroons4j.simple;

import com.github.pvriel.macaroons4j.Caveat;
import org.jetbrains.annotations.NotNull;
import com.github.pvriel.macaroons4j.Macaroon;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.logging.Logger;

/**
 * Class representing a simple {@link Macaroon} implementation.
 * <br>Encryption is accomplished by using AES encryption; the key and IV sizes are defined publicly as static values in this class.
 * <br>The MAC method uses Mac.getInstance("HmacSHA256").
 */
public class SimpleMacaroon extends Macaroon {

    private final static @NotNull Logger logger = Logger.getLogger(SimpleMacaroon.class.getName());
    /**
     * The size of the AES keys.
     */
    public final static int AES_KEY_SIZE = 128 / 8;
    /**
     * The size of the IVs.
     */
    public final static int IV_SIZE = 128 / 8;

    /**
     * Constructor for the {@link SimpleMacaroon} class.
     * @param   secretString
     *          The secret value of the Macaroon, which is required to both generate and verify the signature of the Macaroon instance.
     * @param   macaroonIdentifier
     *          The public identifier of the Macaroon instance.
     * @param   hintTargetLocation
     *          A hint to the target location (which typically issues the Macaroon instance).
     */
    public SimpleMacaroon(@NotNull String secretString, byte[] macaroonIdentifier, @NotNull String hintTargetLocation) {
        super(secretString, macaroonIdentifier, hintTargetLocation);
    }

    /**
     * Constructor for the {@link SimpleMacaroon} class.
     * @param   hintTargetLocation
     *          A hint to the target location (which typically issues the Macaroon instance).
     * @param   macaroonIdentifier
     *          The public identifier of the Macaroon instance.
     * @param   caveats
     *          A set of caveats, which are attached to the Macaroon instance.
     * @param   macaroonSignature
     *          The signature of the Macaroon instance.
     * @param   boundMacaroons
     *          A set of bound Macaroons, which are attached to the Macaroon instance.
     */
    private SimpleMacaroon(@NotNull String hintTargetLocation, byte[] macaroonIdentifier, @NotNull List<@NotNull Caveat> caveats,
                           @NotNull String macaroonSignature, @NotNull Map<ByteBuffer, @NotNull Set<@NotNull Macaroon>> boundMacaroons) {
        super(hintTargetLocation, macaroonIdentifier, caveats, macaroonSignature, boundMacaroons);
    }

    @Override
    public @NotNull Macaroon clone() {
        return new SimpleMacaroon(hintTargetLocation, macaroonIdentifier, caveats, macaroonSignature, boundMacaroons);
    }

    @Override
    protected @NotNull String calculateMAC(@NotNull String key, byte[] element) {
        try {
            Mac sha256HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            sha256HMAC.init(secretKeySpec);

            byte[] result = sha256HMAC.doFinal(element);
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] encrypt(@NotNull String key, byte[] original) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(original);
    }

    @Override
    public @NotNull String decrypt(@NotNull String key, byte[] encrypted) throws InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, key);
        byte[] result = cipher.doFinal(encrypted);
        return new String(result, StandardCharsets.UTF_8);
    }

    private @NotNull Cipher initCipher(int cipherMode, @NotNull String key) throws InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        if (key.length() != AES_KEY_SIZE) {
            logger.fine(String.format("Invalid key length given for Cipher generation (expected length: %d bytes; got: %d bytes).", AES_KEY_SIZE, key.length()));
            if (key.length() < AES_KEY_SIZE) key = key.repeat((int) Math.ceil(16.0/(double) key.length()));
            key = key.substring(0, AES_KEY_SIZE);
        }

        byte[] hashed = calculateSHA256(key.getBytes(StandardCharsets.UTF_8));
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(hashed, 0, iv, 0, IV_SIZE);

        Key keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(cipherMode, keySpec, ivParameterSpec);
        return cipher;
    }

    @Override
    protected @NotNull String bindSignatureForRequest(@NotNull String originalSignature) {
        try {
            return new String(calculateSHA256(originalSignature.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] calculateSHA256(byte[] original) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(original);
    }
}
