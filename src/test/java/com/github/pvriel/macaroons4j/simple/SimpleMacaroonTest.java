package com.github.pvriel.macaroons4j.simple;

import com.github.pvriel.macaroons4j.*;
import com.github.pvriel.macaroons4j.utils.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SimpleMacaroonTest extends MacaroonTest {
    @Override
    protected @NotNull Macaroon generateMacaroon(@NotNull String secretString, byte[] macaroonIdentifier, @NotNull String hintTargetLocation) {
        return new SimpleMacaroon(secretString, macaroonIdentifier, hintTargetLocation);
    }

    @Test
    @DisplayName("Verification contexts can be properly wrapped into a Macaroon.")
    void testWrap() {
        VerificationContext toWrap = new VerificationContext();
        Pair<String, SimpleMacaroon> wrapped = SimpleMacaroon.wrap(toWrap, 256, 256, new HashSet<>());
        String secretKey = wrapped.getKey();
        SimpleMacaroon wrappedMacaroon = wrapped.getValue();
        SimpleMacaroon equivalentMacaroon = new SimpleMacaroon(secretKey, wrappedMacaroon.getMacaroonIdentifier(), new HashSet<>());
        assertEquals(equivalentMacaroon, wrappedMacaroon);

        String membershipUUID = StringUtils.generateRandomStringOfLength(256);
        Set<String> members = Set.of(StringUtils.generateRandomStringOfLength(256), StringUtils.generateRandomStringOfLength(256));
        toWrap.addMembershipConstraint(membershipUUID, members);
        wrapped = SimpleMacaroon.wrap(toWrap, 256, 256, new HashSet<>());
        secretKey = wrapped.getKey();
        wrappedMacaroon = wrapped.getValue();
        equivalentMacaroon = new SimpleMacaroon(secretKey, wrappedMacaroon.getMacaroonIdentifier(), new HashSet<>());
        equivalentMacaroon.addCaveat(new MembershipConstraintFirstPartyCaveat(membershipUUID, new HashSet<>(members)));
        assertEquals(equivalentMacaroon, wrappedMacaroon);

        String rangeUUID = StringUtils.generateRandomStringOfLength(256);
        Pair<Long, Long> range = Pair.of(-100L, 100L);
        toWrap.addRangeConstraint(rangeUUID, range);
        wrapped = SimpleMacaroon.wrap(toWrap, 256, 256, new HashSet<>());
        secretKey = wrapped.getKey();
        wrappedMacaroon = wrapped.getValue();
        equivalentMacaroon = new SimpleMacaroon(secretKey, wrappedMacaroon.getMacaroonIdentifier(), new HashSet<>());
        equivalentMacaroon.addCaveat(new MembershipConstraintFirstPartyCaveat(membershipUUID, new HashSet<>(members)));
        equivalentMacaroon.addCaveat(new RangeConstraintFirstPartyCaveat(rangeUUID, range));
        assertEquals(equivalentMacaroon, wrappedMacaroon);
    }

}
