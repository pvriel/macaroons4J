package com.github.pvriel.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.github.pvriel.macaroons4j.utils.StringUtils.generateRandomStringOfLength;
import static org.junit.jupiter.api.Assertions.*;

public abstract class MacaroonTest {



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
    public void testTwo() {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        HashSet<VerificationContext> contexts = macaroon.verify(macaroonSecret, new VerificationContext());
        assertEquals(contexts.size(), 1);
        assertEquals(new VerificationContext(), contexts.iterator().next());
    }

    @Test
    @DisplayName("A Macaroon with a first-party caveat can be constructed and verified if the caveat holds in the context.")
    public void testThree() {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroonOne = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        FirstPartyCaveat verifiableFirstPartyCaveat = new MockFirstPartyCaveat(generateRandomStringOfLength(256).getBytes(), true);
        macaroonOne.addCaveat(verifiableFirstPartyCaveat);
        HashSet<VerificationContext> contexts = macaroonOne.verify(macaroonSecret, new VerificationContext());
        assertEquals(1, contexts.size());
        assertEquals(new VerificationContext(), contexts.iterator().next());
    }

    @Test
    @DisplayName("A Macaroon with a first-party caveat can not be verified if the caveat does not hold in the context.")
    public void testFour() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroonTwo = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        FirstPartyCaveat nonVerifiableFirstPartyCaveat = new MockFirstPartyCaveat(generateRandomStringOfLength(256).getBytes(), false);
        macaroonTwo.addCaveat(nonVerifiableFirstPartyCaveat);
        HashSet<VerificationContext> contexts = macaroonTwo.verify(macaroonSecret, new VerificationContext());
        assertEquals(0, contexts.size());
    }

    @Test
    @DisplayName("A Macaroon with a third-party caveat can not be verified if there's no corresponding discharge Macaroon (or at least not bound to the Macaroon).")
    public void testFive() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        String thirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        byte[] thirdPartyCaveatIdentifier = generateRandomStringOfLength(256).getBytes();
        ThirdPartyCaveat thirdPartyCaveat = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        macaroon.addCaveat(thirdPartyCaveat);

        HashSet<VerificationContext> contexts = macaroon.verify(macaroonSecret, new VerificationContext());
        assertEquals(0, contexts.size());
    }

    @Test
    @DisplayName("A Macaroon with a third-party caveat can not be verified if the (only) corresponding discharge Macaroon is forged.")
    public void testSix() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        String thirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        byte[] thirdPartyCaveatIdentifier = generateRandomStringOfLength(256).getBytes();
        ThirdPartyCaveat thirdPartyCaveat = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        macaroon.addCaveat(thirdPartyCaveat);

        // A malicious entity forged a discharge Macaroon, without knowing the actual root key of the caveat.
        String forgedThirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        Macaroon forgedDischargeMacaroon = generateMacaroon(forgedThirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "");
        macaroon.bindMacaroonForRequest(forgedDischargeMacaroon);

        HashSet<VerificationContext> contexts = macaroon.verify(macaroonSecret, new VerificationContext());
        assertEquals(0, contexts.size());
    }

    @Test
    @DisplayName("A Macaroon with a third-party caveat can not be verified with a discharge Macaroon of which the caveats do not hold.")
    public void testSeven() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        String thirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        byte[] thirdPartyCaveatIdentifier = generateRandomStringOfLength(256).getBytes();
        ThirdPartyCaveat thirdPartyCaveat = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        macaroon.addCaveat(thirdPartyCaveat);

        Macaroon dischargeMacaroon = generateMacaroon(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "");
        FirstPartyCaveat firstPartyCaveatDischargeMacaroon = new MockFirstPartyCaveat(generateRandomStringOfLength(265).getBytes(), false);
        dischargeMacaroon.addCaveat(firstPartyCaveatDischargeMacaroon);
        macaroon.bindMacaroonForRequest(dischargeMacaroon);

        HashSet<VerificationContext> contexts = macaroon.verify(macaroonSecret, new VerificationContext());
        assertEquals(0, contexts.size());
    }

    @Test
    @DisplayName("Discharge Macaroons can not be bound to other discharge Macaroons.")
    public void testEight() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroonOne = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);
        Macaroon macaroonTwo = generateRandomMacaroon();
        Macaroon macaroonThree = generateRandomMacaroon();

        macaroonTwo.bindMacaroonForRequest(macaroonThree);
        assertThrows(IllegalArgumentException.class, () -> macaroonOne.bindMacaroonForRequest(macaroonTwo));
    }

    @Test
    @DisplayName("Forged signatures are detected.")
    public void testNine() {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);
        macaroon.setMacaroonSignature(generateRandomStringOfLength(256));

        HashSet<VerificationContext> validContexts = macaroon.verify(macaroonSecret, new VerificationContext());
        assertEquals(0, validContexts.size());
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
        Macaroon macaroon = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

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
            public @NotNull FirstPartyCaveat clone() {
                return new AlteringValidityFirstPartyCaveat(getCaveatIdentifier());
            }

            @Override
            public void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException {
                boolean myValue = alteringFirstPartyCaveatIsValid.get();
                alteringFirstPartyCaveatIsValid.set(!myValue);

                if (!myValue) throw new IllegalStateException("myValue is set to false.");
            }
        }
        Macaroon dischargeMacaroonOne = generateMacaroon(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "testOne");
        Macaroon dischargeMacaroonTwo = generateMacaroon(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "testTwo");
        dischargeMacaroonOne.addCaveat(new AlteringValidityFirstPartyCaveat(generateRandomStringOfLength(265).getBytes(StandardCharsets.UTF_8)));
        dischargeMacaroonTwo.addCaveat(new AlteringValidityFirstPartyCaveat(generateRandomStringOfLength(265).getBytes(StandardCharsets.UTF_8)));
        macaroon.bindMacaroonForRequest(dischargeMacaroonOne);
        macaroon.bindMacaroonForRequest(dischargeMacaroonTwo);

        HashSet<VerificationContext> contexts = macaroon.verify(macaroonSecret, new VerificationContext());
        assertEquals(1, contexts.size());
        assertEquals(new VerificationContext(), contexts.iterator().next());
        assertFalse(alteringFirstPartyCaveatIsValid.get());
    }

    @Test
    @DisplayName("Already verified discharge Macaroons should not be verified multiple times.")
    void testEleven() throws Exception {
        String hintTargetLocation = generateRandomStringOfLength(256);
        byte[] macaroonIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = generateMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);

        String thirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        byte[] thirdPartyCaveatIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        ThirdPartyCaveat thirdPartyCaveatOne = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        ThirdPartyCaveat thirdPartyCaveatTwo = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        macaroon.addCaveat(thirdPartyCaveatOne);
        macaroon.addCaveat(thirdPartyCaveatTwo);

        Macaroon dischargeMacaroonOne = generateMacaroon(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "");
        MockFirstPartyCaveat dischargeMacaroonFirstPartyCaveat = new MockFirstPartyCaveat(generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8), true);
        dischargeMacaroonFirstPartyCaveat = (MockFirstPartyCaveat) dischargeMacaroonOne.addCaveat(dischargeMacaroonFirstPartyCaveat);
        macaroon.bindMacaroonForRequest(dischargeMacaroonOne);

        HashSet<VerificationContext> results = macaroon.verify(macaroonSecret, new VerificationContext());
        assertEquals(1, results.size());
        assertEquals(new VerificationContext(), results.iterator().next());
        assertEquals(1, dischargeMacaroonFirstPartyCaveat.amountOfVerifications);
    }

    @Test
    @DisplayName("Invalid discharge Macaroons should not be verified multiple times.")
    void testTwelve() throws Exception {
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = generateMacaroon(macaroonSecret, generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8), generateRandomStringOfLength(256));

        String thirdPartyCaveatSecretKey = generateRandomStringOfLength(256);
        byte[] thirdPartyCaveatIdentifier = generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8);
        ThirdPartyCaveat thirdPartyCaveatOne = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        ThirdPartyCaveat thirdPartyCaveatTwo = new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier);
        macaroon.addCaveat(thirdPartyCaveatOne);
        macaroon.addCaveat(thirdPartyCaveatTwo);

        Macaroon invalidDischargeMacaroon = generateMacaroon(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "");
        Macaroon validDischargeMacaroon = generateMacaroon(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier, "");
        MockFirstPartyCaveat invalidDischargeMacaroonFirstPartyCaveat = new MockFirstPartyCaveat(generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8), false);
        MockFirstPartyCaveat validDischargeMacaroonFirstPartyCaveat = new MockFirstPartyCaveat(generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8), true);
        invalidDischargeMacaroonFirstPartyCaveat = (MockFirstPartyCaveat) invalidDischargeMacaroon.addCaveat(invalidDischargeMacaroonFirstPartyCaveat);
        validDischargeMacaroonFirstPartyCaveat = (MockFirstPartyCaveat) validDischargeMacaroon.addCaveat(validDischargeMacaroonFirstPartyCaveat);
        validDischargeMacaroon.addCaveat(new MockThirdPartyCaveat(thirdPartyCaveatSecretKey, thirdPartyCaveatIdentifier));
        macaroon.bindMacaroonForRequest(invalidDischargeMacaroon);
        macaroon.bindMacaroonForRequest(validDischargeMacaroon);

        HashSet<VerificationContext> results = macaroon.verify(macaroonSecret, new VerificationContext());
        assertEquals(1, results.size());
        assertEquals(new VerificationContext(), results.iterator().next());
        assertTrue(1 >= invalidDischargeMacaroonFirstPartyCaveat.amountOfVerifications);
        assertEquals(1, validDischargeMacaroonFirstPartyCaveat.amountOfVerifications);
    }

    @Test
    void testEquals() throws Exception {
        Macaroon macaroon = generateRandomMacaroon();
        macaroon.addCaveat(new MembershipConstraintFirstPartyCaveat(generateRandomStringOfLength(256), new HashSet<>(Set.of(generateRandomStringOfLength(256)))));
        macaroon.addCaveat(new RangeConstraintFirstPartyCaveat(generateRandomStringOfLength(256), 0L, 100L));
        macaroon.addCaveat(new ThirdPartyCaveat(generateRandomStringOfLength(256), generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8), generateRandomStringOfLength(256)));
        Macaroon clone = macaroon.clone();
        assertEquals(macaroon, clone);
    }

    @Test
    @DisplayName("All verification contexts are returned after the verification process of a Macaroon.")
    void test13() throws Exception {
        String macaroonSecret = generateRandomStringOfLength(256);
        Macaroon macaroon = generateMacaroon(macaroonSecret, generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8), generateRandomStringOfLength(256));

        String dischargeMacaroonSecret = generateRandomStringOfLength(256);
        String dischargeMacaroonIdentifier = generateRandomStringOfLength(256);
        ThirdPartyCaveat thirdPartyCaveat = new ThirdPartyCaveat(dischargeMacaroonSecret, dischargeMacaroonIdentifier.getBytes(StandardCharsets.UTF_8), "");
        macaroon.addCaveat(thirdPartyCaveat);
        macaroon.addCaveat(new RangeConstraintFirstPartyCaveat("TIME", 0L, 100L));

        Macaroon validDischargeMacaroonOne = generateMacaroon(dischargeMacaroonSecret, dischargeMacaroonIdentifier.getBytes(StandardCharsets.UTF_8), "");
        validDischargeMacaroonOne.addCaveat(new MembershipConstraintFirstPartyCaveat("ACCESS", new HashSet<>(Set.of("resourceOne"))));
        validDischargeMacaroonOne.addCaveat(new RangeConstraintFirstPartyCaveat("TIME", -100L, 0L));
        macaroon.bindMacaroonForRequest(validDischargeMacaroonOne);

        Macaroon validDischargeMacaroonTwo = generateMacaroon(dischargeMacaroonSecret, dischargeMacaroonIdentifier.getBytes(StandardCharsets.UTF_8), "");
        validDischargeMacaroonTwo.addCaveat(new MembershipConstraintFirstPartyCaveat("ACCESS", new HashSet<>(Set.of("resourceTwo"))));
        validDischargeMacaroonTwo.addCaveat(new RangeConstraintFirstPartyCaveat("TIME", 100L, 200L));
        macaroon.bindMacaroonForRequest(validDischargeMacaroonTwo);

        Macaroon invalidDischargeMacaroonThree = generateMacaroon(dischargeMacaroonSecret, dischargeMacaroonIdentifier.getBytes(StandardCharsets.UTF_8), "");
        invalidDischargeMacaroonThree.addCaveat(new RangeConstraintFirstPartyCaveat("TIME", 200L, 300L));
        macaroon.bindMacaroonForRequest(invalidDischargeMacaroonThree);

        VerificationContext expectedResultOne = new VerificationContext();
        expectedResultOne.addMembershipConstraint("ACCESS", Set.of("resourceOne"));
        expectedResultOne.addRangeConstraint("TIME", 0L, 0L);
        VerificationContext expectedResultTwo = new VerificationContext();
        expectedResultTwo.addMembershipConstraint("ACCESS", Set.of("resourceTwo"));
        expectedResultTwo.addRangeConstraint("TIME", 100L, 100L);
        HashSet<VerificationContext> expectedResults = new HashSet<>(Set.of(expectedResultOne, expectedResultTwo));
        HashSet<VerificationContext> results = macaroon.verify(macaroonSecret, new VerificationContext());
        assertEquals(expectedResults, results);
    }

    @Test
    @DisplayName("The delete / constraint copy methods work properly.")
    void test14() {
        VerificationContext verificationContext = new VerificationContext();
        verificationContext.addMembershipConstraint("ACCESS", Set.of("resourceOne"));
        verificationContext.addRangeConstraint("TIME", 0L, 0L);

        assertEquals(new HashMap<>(Map.of("ACCESS", Set.of("resourceOne"))), verificationContext.getCopyOfMembershipConstraints());
        assertEquals(new HashMap<>(Map.of("TIME", Pair.of(0L, 0L))), verificationContext.getCopyOfRangeConstraints());
        assertEquals(new HashSet<>(Set.of("ACCESS")), verificationContext.getCopyOfMembershipConstraintUUIDs());
        assertEquals(new HashSet<>(Set.of("TIME")), verificationContext.getCopyOfRangeConstraintUUIDs());
        assertEquals("VerificationContext{TIME ∈ [0, 0], ACCESS ∈ [resourceOne]}", verificationContext.toString());

        verificationContext.removeMembershipConstraint("ACCESS");
        assertEquals(new HashMap<>(), verificationContext.getCopyOfMembershipConstraints());
        assertEquals(new HashMap<>(Map.of("TIME", Pair.of(0L, 0L))), verificationContext.getCopyOfRangeConstraints());
        assertEquals(new HashSet<>(), verificationContext.getCopyOfMembershipConstraintUUIDs());
        assertEquals(new HashSet<>(Set.of("TIME")), verificationContext.getCopyOfRangeConstraintUUIDs());
        assertEquals("VerificationContext{TIME ∈ [0, 0]}", verificationContext.toString());

        verificationContext.removeRangeConstraint("TIME");
        assertEquals(new HashMap<>(), verificationContext.getCopyOfMembershipConstraints());
        assertEquals(new HashMap<>(), verificationContext.getCopyOfRangeConstraints());
        assertEquals(new HashSet<>(), verificationContext.getCopyOfMembershipConstraintUUIDs());
        assertEquals(new HashSet<>(), verificationContext.getCopyOfRangeConstraintUUIDs());
        assertEquals("VerificationContext{}", verificationContext.toString());
    }

    @Test
    @DisplayName("The third-party caveats for specific target locations can be properly found.")
    public void test15() throws Exception {
        String locationOne = generateRandomStringOfLength(256);
        String locationTwo = generateRandomStringOfLength(256);
        String locationThree = generateRandomStringOfLength(256);

        String secretKeyThirdPartyCaveatOne = generateRandomStringOfLength(256);
        Macaroon macaroon = generateRandomMacaroon();
        macaroon.addCaveat(new MembershipConstraintFirstPartyCaveat(generateRandomStringOfLength(256), new HashSet<>(Set.of(generateRandomStringOfLength(256)))));
        ThirdPartyCaveat thirdPartyCaveatOne = new ThirdPartyCaveat(secretKeyThirdPartyCaveatOne, generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8), Set.of(locationOne, locationTwo));
        ThirdPartyCaveat thirdPartyCaveatTwo = new ThirdPartyCaveat(generateRandomStringOfLength(256), generateRandomStringOfLength(256).getBytes(StandardCharsets.UTF_8), Set.of(locationOne, locationTwo));
        thirdPartyCaveatOne = macaroon.addCaveat(thirdPartyCaveatOne);
        macaroon.addCaveat(thirdPartyCaveatTwo);

        Macaroon dischargeMacaroonThirdPartyCaveatTwo = generateMacaroon(secretKeyThirdPartyCaveatOne, thirdPartyCaveatTwo.getCaveatIdentifier(), "");
        macaroon.bindMacaroonForRequest(dischargeMacaroonThirdPartyCaveatTwo);

        HashSet<String> possibleLocations = new HashSet<>(Set.of(locationTwo, locationThree));
        HashSet<ThirdPartyCaveat> foundCaveats = macaroon.getAllNonDischargedThirdPartyCaveats(possibleLocations);
        assertEquals(1, foundCaveats.size());
        assertEquals(thirdPartyCaveatOne, foundCaveats.iterator().next());
    }


    private static class MockFirstPartyCaveat extends FirstPartyCaveat {

        private final boolean shouldVerify;
        int amountOfVerifications = 0;

        MockFirstPartyCaveat(byte[] caveatIdentifier, boolean shouldVerify) {
            super(caveatIdentifier);
            this.shouldVerify = shouldVerify;
        }

        @Override
        public void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException {
            amountOfVerifications ++;
            if (!shouldVerify) throw new IllegalStateException("shouldVerify of caveat (%s) is set to false.".formatted(this));
        }

        @Override
        public @NotNull FirstPartyCaveat clone() {
            return new MockFirstPartyCaveat(getCaveatIdentifier(), shouldVerify);
        }
    }

    private static class MockThirdPartyCaveat extends ThirdPartyCaveat {

        MockThirdPartyCaveat(String caveatRootKey, byte[] caveatIdentifier) {
            super(caveatRootKey, caveatIdentifier, "");
        }
    }
}