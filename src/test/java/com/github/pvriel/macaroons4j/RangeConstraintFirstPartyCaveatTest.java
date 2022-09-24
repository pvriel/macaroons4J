package com.github.pvriel.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import com.github.pvriel.macaroons4j.simple.SimpleMacaroon;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class RangeConstraintFirstPartyCaveatTest {

    @Test
    @DisplayName("A range constraint can not be constructed with a lower bound that is greater than the upper bound.")
    void testOne() {
        assertThrows(IllegalArgumentException.class, () -> new RangeConstraintFirstPartyCaveat(UUID.randomUUID().toString(), 2, 1));
    }

    @Test
    @DisplayName("A range constraint can be constructed and verified in an empty context.")
    void testTwo() {
        RangeConstraintFirstPartyCaveat rangeConstraintFirstPartyCaveat = new RangeConstraintFirstPartyCaveat(UUID.randomUUID().toString(), 1, 2);
        VerificationContext verificationContext = new VerificationContext();
        Macaroon emptyMacaroon = new SimpleMacaroon(UUID.randomUUID().toString(), UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8), UUID.randomUUID().toString());

        assertDoesNotThrow(() -> rangeConstraintFirstPartyCaveat.verify(emptyMacaroon, verificationContext));
    }

    @Test
    @DisplayName("A range constraint can be constructed and verified in a context with an corresponding and overlapping range constraint.")
    void testThree() {
        String rangeUUID = UUID.randomUUID().toString();
        VerificationContext initialContext = new VerificationContext();
        initialContext.addRangeConstraint(rangeUUID, Pair.of((long) -1, (long) 1));
        Macaroon emptyMacaroon = new SimpleMacaroon(UUID.randomUUID().toString(), UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8), UUID.randomUUID().toString());

        VerificationContext contextOne = initialContext.clone();
        RangeConstraintFirstPartyCaveat rangeConstraintFirstPartyCaveatOne = new RangeConstraintFirstPartyCaveat(rangeUUID, -1, 1);
        assertDoesNotThrow(() -> rangeConstraintFirstPartyCaveatOne.verify(emptyMacaroon, contextOne));

        VerificationContext contextTwo = initialContext.clone();
        RangeConstraintFirstPartyCaveat rangeConstraintFirstPartyCaveatTwo = new RangeConstraintFirstPartyCaveat(rangeUUID, -2, 0);
        assertDoesNotThrow(() -> rangeConstraintFirstPartyCaveatTwo.verify(emptyMacaroon, contextTwo));
        assertEquals(Pair.of((long) -1, (long) 0), contextTwo.getRangeConstraints().get(rangeUUID));

        VerificationContext contextThree = initialContext.clone();
        RangeConstraintFirstPartyCaveat rangeConstraintFirstPartyCaveatThree = new RangeConstraintFirstPartyCaveat(rangeUUID, 0, 2);
        assertDoesNotThrow(() -> rangeConstraintFirstPartyCaveatThree.verify(emptyMacaroon, contextThree));
        assertEquals(Pair.of((long) 0, (long) 1), contextThree.getRangeConstraints().get(rangeUUID));
    }

    @Test
    @DisplayName("A range constraint can not be verified when the corresponding range from the context does not overlap with the range of the range constraint.")
    void testFour() {
        String rangeUUID = UUID.randomUUID().toString();
        VerificationContext initialContext = new VerificationContext();
        initialContext.addRangeConstraint(rangeUUID, Pair.of((long) -1, (long) 1));
        Macaroon emptyMacaroon = new SimpleMacaroon(UUID.randomUUID().toString(), UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8), UUID.randomUUID().toString());

        VerificationContext contextOne = initialContext.clone();
        RangeConstraintFirstPartyCaveat rangeConstraintFirstPartyCaveatOne = new RangeConstraintFirstPartyCaveat(rangeUUID, -3, -2);
        assertThrows(Exception.class, () -> rangeConstraintFirstPartyCaveatOne.verify(emptyMacaroon, contextOne));

        VerificationContext contextTwo = initialContext.clone();
        RangeConstraintFirstPartyCaveat rangeConstraintFirstPartyCaveatTwo = new RangeConstraintFirstPartyCaveat(rangeUUID, 2, 3);
        assertThrows(Exception.class, () -> rangeConstraintFirstPartyCaveatTwo.verify(emptyMacaroon, contextTwo));
    }
}