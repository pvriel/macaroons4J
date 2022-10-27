package com.github.pvriel.macaroons4j.utils;

import org.jetbrains.annotations.NotNull;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Class representing some {@link String} utils.
 */
public abstract class StringUtils {

    private static final String allowedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Random random = new SecureRandom();

    /**
     * Method to generate a random string with a given length.
     * @param   length
     *          The length of the random string.
     * @return  The String.
     */
    @NotNull
    public static String generateRandomStringOfLength(int length) {
        StringBuilder stringBuilder = new StringBuilder(length);
        for (int i = 0; i < length; i ++) stringBuilder.append(allowedCharacters.charAt(random.nextInt(allowedCharacters.length())));
        return stringBuilder.toString();
    }
}
