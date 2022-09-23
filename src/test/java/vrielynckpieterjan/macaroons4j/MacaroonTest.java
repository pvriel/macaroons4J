package vrielynckpieterjan.macaroons4j;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.macaroons4j.simple.SimpleMacaroon;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

public abstract class MacaroonTest {

    private static final String allowedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Random random = new SecureRandom();

    protected abstract @NotNull Macaroon generateMacaroon(@NotNull String secretString, byte[] macaroonIdentifier, @NotNull String hintTargetLocation);

    private @NotNull Macaroon generateRandomMacaroon() {
        return generateMacaroon(generateRandomStringOfLength(256), generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8), generateRandomStringOfLength(256));
    }

    @Test
    @DisplayName("Encrypted elements can be correctly decrypted.")
    public void testOne() throws Exception {
        Macaroon macaroon = generateRandomMacaroon();
        String toEncrypt = generateRandomStringOfLength(256);
        String key = generateRandomStringOfLength(256);

        byte[] encrypted = macaroon.encrypt(key, toEncrypt.getBytes(StandardCharsets.UTF_8));
        String decrypted = macaroon.decrypt(key, encrypted);
        assertEquals(decrypted, toEncrypt);
    }

    @Test
    @DisplayName("A Macaroon without any caveats can always be constructed and verified.")
    public void testTwo() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        assertDoesNotThrow(() -> macaroon.verify(macaroonSecret, new VerificationContext()));
    }

    @Test
    @DisplayName("A Macaroon with a first-party caveat can be constructed and verified if the caveat holds in the context.")
    public void testThree() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroonOne = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        FirstPartyCaveat verifiableFirstPartyCaveat = new MockFirstPartyCaveat(generateRandomStringOfLength(256).getBytes(), true);
        macaroonOne.addCaveat(verifiableFirstPartyCaveat);
        assertDoesNotThrow(() -> macaroonOne.verify(macaroonSecret, new VerificationContext()));
    }

    @Test
    @DisplayName("A Macaroon with a first-party caveat can not be verified if the caveat does not hold in the context.")
    public void testFour() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroonTwo = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        FirstPartyCaveat nonVerifiableFirstPartyCaveat = new MockFirstPartyCaveat(generateRandomStringOfLength(256).getBytes(), false);
        macaroonTwo.addCaveat(nonVerifiableFirstPartyCaveat);
        assertThrows(IllegalStateException.class, () -> macaroonTwo.verify(macaroonSecret, new VerificationContext()));
    }

    @Test
    @DisplayName("A Macaroon with a third-party caveat can not be verified if there's no corresponding discharge Macaroon (or at least not bound to the Macaroon).")
    public void testFive() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        String thirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        byte[] thirdPartyCaveatIdentifier = generateRandomStringOfLength(256).getBytes();
        ThirdPartyCaveat thirdPartyCaveat = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        macaroon.addCaveat(thirdPartyCaveat);

        assertThrows(IllegalStateException.class, () -> macaroon.verify(macaroonSecret, new VerificationContext()));
    }

    @Test
    @DisplayName("A Macaroon with a third-party caveat can not be verified if the (only) corresponding discharge Macaroon is forged.")
    public void testSix() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        String thirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        byte[] thirdPartyCaveatIdentifier = generateRandomStringOfLength(256).getBytes();
        ThirdPartyCaveat thirdPartyCaveat = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        macaroon.addCaveat(thirdPartyCaveat);

        // A malicious entity forged a discharge Macaroon, without knowing the actual root key of the caveat.
        String forgedThirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        Macaroon forgedDischargeMacaroon = new SimpleMacaroon(forgedThirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "");
        macaroon.bindMacaroonForRequest(forgedDischargeMacaroon);

        assertThrows(IllegalStateException.class, () -> macaroon.verify(macaroonSecret, new VerificationContext()));
    }

    @Test
    @DisplayName("A Macaroon with a third-party caveat can not be verified with a discharge Macaroon of which the caveats do not hold.")
    public void testSeven() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        String thirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        byte[] thirdPartyCaveatIdentifier = generateRandomStringOfLength(256).getBytes();
        ThirdPartyCaveat thirdPartyCaveat = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        macaroon.addCaveat(thirdPartyCaveat);

        Macaroon dischargeMacaroon = new SimpleMacaroon(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "");
        FirstPartyCaveat firstPartyCaveatDischargeMacaroon = new MockFirstPartyCaveat(generateRandomStringOfLength(265).getBytes(), false);
        dischargeMacaroon.addCaveat(firstPartyCaveatDischargeMacaroon);
        macaroon.bindMacaroonForRequest(dischargeMacaroon);

        assertThrows(IllegalStateException.class, () -> macaroon.verify(macaroonSecret, new VerificationContext()));
    }

    @Test
    @DisplayName("Discharge Macaroons can not be bound to other discharge Macaroons during the verification process.")
    public void testEight() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroonOne = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);
        Macaroon macaroonTwo = generateRandomMacaroon();
        Macaroon macaroonThree = generateRandomMacaroon();

        macaroonTwo.bindMacaroonForRequest(macaroonThree);
        macaroonOne.bindMacaroonForRequest(macaroonTwo);

        assertThrows(IllegalStateException.class, () -> macaroonOne.verify(macaroonSecret, new VerificationContext()));
    }

    @Test
    @DisplayName("Forged signatures are detected.")
    public void testNine() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);
        macaroon.macaroonSignature = generateRandomStringOfLength(256);

        assertThrows(IllegalStateException.class, () -> macaroon.verify(macaroonSecret, new VerificationContext()));
    }

    @Test
    @DisplayName("The verification process of a Macaroon should succeed if each third-party caveat can be discharged by at least one discharge Macaroon in a valid context.")
    public void testTen() throws Exception {
        /*
        What should happen:
            -   We create a Macaroon with a third-party caveat and a first-party caveat, in the exact order.
                The third-party caveat always holds.
                The first-party caveat only holds if the amount of times that the third-party caveat has been verified % 2 == 0.
            -   We bind two discharge Macaroons to the third-party caveat. According to the previous note, that means that the verification process of the Macaroon
                with the first discharge Macaroon should fail, while the verification process with the second discharge Macaroon should succeed.
                Therefore, the verification process should succeed in general, because at least one discharge Macaroon that can be used
                to discharge the third-party caveat in a context for which the first-party caveat also holds.
         */
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        String thirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        byte[] thirdPartyCaveatIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        ThirdPartyCaveat thirdPartyCaveat = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        macaroon.addCaveat(thirdPartyCaveat);

        AtomicBoolean alteringFirstPartyCaveatIsValid = new AtomicBoolean(false);
        class AlteringValidityFirstPartyCaveat extends FirstPartyCaveat {

            protected AlteringValidityFirstPartyCaveat(byte[] caveatIdentifier) {
                super(caveatIdentifier);
            }

            @Override
            protected void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException {
                boolean myValue = alteringFirstPartyCaveatIsValid.get();
                alteringFirstPartyCaveatIsValid.set(!myValue);

                if (!myValue) throw new IllegalStateException("myValue is set to false.");
            }
        }
        Macaroon dischargeMacaroonOne = new SimpleMacaroon(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "");
        Macaroon dischargeMacaroonTwo = new SimpleMacaroon(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "");
        dischargeMacaroonOne.addCaveat(new AlteringValidityFirstPartyCaveat(generateRandomStringOfLength(265).getBytes(StandardCharsets.UTF_8)));
        dischargeMacaroonTwo.addCaveat(new AlteringValidityFirstPartyCaveat(generateRandomStringOfLength(265).getBytes(StandardCharsets.UTF_8)));
        macaroon.bindMacaroonForRequest(dischargeMacaroonOne);
        macaroon.bindMacaroonForRequest(dischargeMacaroonTwo);

        assertDoesNotThrow(() -> macaroon.verify(macaroonSecret, new VerificationContext()));
        assertFalse(alteringFirstPartyCaveatIsValid.get());
    }

    // D. If there is a corresponding discharge macaroon and its caveats hold in the context, the verification process should succeed.

    // E. If there are multiple corresponding discharge macaroons, the verification process should succeed if the caveats of at least one discharge macaroon hold.

    private static String generateRandomStringOfLength(int length) {
        StringBuilder stringBuilder = new StringBuilder(length);
        for (int i = 0; i < length; i ++) stringBuilder.append(allowedCharacters.charAt(random.nextInt(allowedCharacters.length())));
        return stringBuilder.toString();
    }


    private static class MockFirstPartyCaveat extends FirstPartyCaveat {

        private final boolean shouldVerify;

        MockFirstPartyCaveat(byte[] caveatIdentifier, boolean shouldVerify) {
            super(caveatIdentifier);
            this.shouldVerify = shouldVerify;
        }

        @Override
        protected void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException {
            if (!shouldVerify) throw new IllegalStateException("shouldVerify of caveat (%s) is set to false.".formatted(this));
        }
    }

    private static class MockThirdPartyCaveat extends ThirdPartyCaveat {

        MockThirdPartyCaveat(String caveatRootKey, byte[] caveatIdentifier) {
            super(caveatRootKey, caveatIdentifier, "");
        }
    }
}