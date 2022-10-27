package com.github.pvriel.macaroons4j;

import com.github.pvriel.macaroons4j.simple.SimpleMacaroon;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class MembershipConstraintFirstPartyCaveatTest {

    @Test
    @DisplayName("A membership constraint can not be constructed with members with illegal character sequences.")
    void testOne() {
        String membershipUUID = UUID.randomUUID().toString();
        HashSet<String> requiredMembers = new HashSet<>();
        requiredMembers.add("test, me");

        assertThrows(IllegalArgumentException.class, () -> new MembershipConstraintFirstPartyCaveat(membershipUUID, requiredMembers));
    }

    @Test
    @DisplayName("A membership constraint can be constructed with no members at all.")
    void testTwo() {
        String membershipUUID = UUID.randomUUID().toString();
        HashSet<String> requiredMembers = new HashSet<>();

        assertDoesNotThrow(() -> new MembershipConstraintFirstPartyCaveat(membershipUUID, requiredMembers));
    }

    @Test
    @DisplayName("A membership constraint can be constructed and verified in an empty context.")
    void testThree() {
        String membershipUUID = UUID.randomUUID().toString();
        HashSet<String> requiredMembers = new HashSet<>();
        requiredMembers.add(UUID.randomUUID().toString());
        requiredMembers.add(UUID.randomUUID().toString());

        MembershipConstraintFirstPartyCaveat membershipConstraintFirstPartyCaveat = new MembershipConstraintFirstPartyCaveat(membershipUUID, requiredMembers);
        VerificationContext verificationContext = new VerificationContext();
        Macaroon emptyMacaroon = new SimpleMacaroon(UUID.randomUUID().toString(), UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8), UUID.randomUUID().toString());

        assertDoesNotThrow(() -> membershipConstraintFirstPartyCaveat.verify(emptyMacaroon, verificationContext));
    }

    @Test
    @DisplayName("A membership constraint can be constructed and verified in a context that supports the membership constraint.")
    void testFour() {
        String membershipUUID = UUID.randomUUID().toString();
        HashSet<String> requiredMembers = new HashSet<>();
        requiredMembers.add(UUID.randomUUID().toString());
        requiredMembers.add(UUID.randomUUID().toString());

        MembershipConstraintFirstPartyCaveat membershipConstraintFirstPartyCaveat = new MembershipConstraintFirstPartyCaveat(membershipUUID, requiredMembers);
        VerificationContext verificationContext = new VerificationContext();
        Macaroon emptyMacaroon = new SimpleMacaroon(UUID.randomUUID().toString(), UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8), UUID.randomUUID().toString());

        HashSet<String> currentlySupportedElements = new HashSet<>(requiredMembers);
        currentlySupportedElements.add(UUID.randomUUID().toString());
        verificationContext.addMembershipConstraint(membershipUUID, currentlySupportedElements);

        assertDoesNotThrow(() -> membershipConstraintFirstPartyCaveat.verify(emptyMacaroon, verificationContext));
        assertEquals(requiredMembers, verificationContext.getCopyOfMembershipConstraints().get(membershipUUID));
    }

    @Test
    @DisplayName("The verification process of a membership constraint fails when the constraint contains members that are not supported by the context.")
    void testFive() {
        String membershipUUID = UUID.randomUUID().toString();
        HashSet<String> requiredMembers = new HashSet<>();
        requiredMembers.add(UUID.randomUUID().toString());
        requiredMembers.add(UUID.randomUUID().toString());
        HashSet<String> currentlySupportedElements = new HashSet<>(requiredMembers);
        requiredMembers.add(UUID.randomUUID().toString()); // Is required by caveat, by not supported by context.

        MembershipConstraintFirstPartyCaveat membershipConstraintFirstPartyCaveat = new MembershipConstraintFirstPartyCaveat(membershipUUID, requiredMembers);
        VerificationContext verificationContext = new VerificationContext();
        Macaroon emptyMacaroon = new SimpleMacaroon(UUID.randomUUID().toString(), UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8), UUID.randomUUID().toString());

        verificationContext.addMembershipConstraint(membershipUUID, currentlySupportedElements);

        assertThrows(Exception.class, () -> membershipConstraintFirstPartyCaveat.verify(emptyMacaroon, verificationContext));
    }
}