package com.github.pvriel.macaroons4j;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static com.github.pvriel.macaroons4j.MacaroonTest.generateRandomStringOfLength;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ThirdPartyCaveatTest {

    @Test
    void testEquals() {
        String secretKey = generateRandomStringOfLength(256);
        byte[] identifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String location = generateRandomStringOfLength(256);
        ThirdPartyCaveat thirdPartyCaveatOne = new ThirdPartyCaveat(secretKey, identifier, location);
        ThirdPartyCaveat thirdPartyCaveatTwo = new ThirdPartyCaveat(secretKey, identifier, location);
        assertEquals(thirdPartyCaveatOne, thirdPartyCaveatTwo);
    }
}