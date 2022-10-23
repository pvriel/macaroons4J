package com.github.pvriel.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Class representing contexts in which {@link Macaroon} instances can be verified.
 */
public class VerificationContext {

    /**
     * Map representing the membership constraints, mapping their UUIDs to the elements of the membership.
     */
    public final @NotNull Map<@NotNull String, @NotNull Set<@NotNull String>> membershipConstraints;
    /**
     * Map representing the range constraints, mapping their UUIDs to the range.
     */
    public final @NotNull Map<@NotNull String, @NotNull Pair<@NotNull Long, @NotNull Long>> rangeConstraints;
    private final @NotNull Set<ByteBuffer> alreadyVerifiedCaveatIdentifiers;
    private final @NotNull Set<@NotNull Macaroon> invalidDischargeMacaroons;

    /**
     * Default constructor for the {@link VerificationContext} class.
     */
    public VerificationContext() {
        this(new HashMap<>(), new HashMap<>(), new HashSet<>(), new HashSet<>());
    }

    /**
     * Method to add a membership constraint to the verification context.
     * <br>If the method is called for a first time for a specific membership UUID, the membership is just set to the given elements.
     * <br>If the method is called again for a specific membership UUID, the membership is only updated if the given set is a (sub-)set
     * of the set that was used to call the method the previous time. Otherwise, this method throws an {@link IllegalStateException}.
     * @param   membershipUUID
     *          The UUID of the membership.
     * @param   shouldContainElements
     *          The elements that should be included in the membership.
     */
    public void addMembershipConstraint(@NotNull String membershipUUID, @NotNull Set<@NotNull String> shouldContainElements) throws IllegalStateException {
        if (!membershipConstraints.containsKey(membershipUUID)) {
            membershipConstraints.put(membershipUUID, shouldContainElements);
            return;
        }

        Set<String> existingElements = membershipConstraints.get(membershipUUID);
        Set<String> copyOfShouldContainElements = new HashSet<>(shouldContainElements);
        copyOfShouldContainElements.retainAll(existingElements);
        if (copyOfShouldContainElements.size() != shouldContainElements.size()) {
            throw new IllegalStateException("The membership constraint with the UUID '" + membershipUUID + "' already exists, but the elements to further restrict this constraint to are not a subset of the existing elements.");
        }

        membershipConstraints.put(membershipUUID, copyOfShouldContainElements);
    }

    /**
     * Method to add a range constraint to the verification context.
     * <br>If the method is called for a first time for a specific range UUID, the range is just set.
     * <br>If the method is called again for a specific range UUID, the range is only updated to the overlap, if the given range overlaps
     * with the current range. Otherwise, this method throws an {@link IllegalStateException}.
     * @param   rangeUUID
     *          The UUID of the range.
     * @param   range
     *          The new range.
     * @throws  IllegalStateException
     *          If a range has already been defined for the given UUID, but it does not overlap with the given range of this method invocation.
     */
    public void addRangeConstraint(@NotNull String rangeUUID, @NotNull Pair<@NotNull Long, @NotNull Long> range) throws IllegalStateException {
        long startNewRange = range.getLeft();
        long endNewRange = range.getRight();
        if (startNewRange > endNewRange) throw new IllegalArgumentException("The start of the range is at a later moment than the end of the range.");

        if (rangeConstraints.containsKey(rangeUUID)) {
            Pair<Long, Long> oldRange = rangeConstraints.get(rangeUUID);
            long startOldRange = oldRange.getLeft();
            long endOldRange = oldRange.getRight();
            if (startNewRange > endOldRange || endNewRange < startOldRange) {
                throw new IllegalStateException("The range constraint with the UUID '" + rangeUUID + "' already exists, but the new range is not a subset of the existing range.");
            }

            startNewRange = Math.max(startNewRange, startOldRange);
            endNewRange = Math.min(endNewRange, endOldRange);
            rangeConstraints.put(rangeUUID, Pair.of(startNewRange, endNewRange));
        } else {
            rangeConstraints.put(rangeUUID, range);
        }
    }

    /**
     * Method to add a range constraint to the verification context.
     * <br>If the method is called for a first time for a specific range UUID, the range is just set.
     * <br>If the method is called again for a specific range UUID, the range is only updated to the overlap, if the given range overlaps
     * with the current range. Otherwise, this method throws an {@link IllegalStateException}.
     * @param   rangeUUID
     *          The UUID of the range.
     * @param   lowerBound
     *          The lower bound of the range.
     * @param   upperBound
     *          The upper bound of the range.
     * @throws  IllegalStateException
     *          If a range has already been defined for the given UUID, but it does not overlap with the given range of this method invocation.
     */
    public void addRangeConstraint(@NotNull String rangeUUID, long lowerBound, long upperBound) throws IllegalStateException {
        addRangeConstraint(rangeUUID, Pair.of(lowerBound, upperBound));
    }

    boolean caveatIdentifierIsAlreadyVerified(byte[] identifier) {
        return alreadyVerifiedCaveatIdentifiers.contains(ByteBuffer.wrap(identifier));
    }

    void addAlreadyVerifiedCaveatIdentifier(byte[] identifier) {
        alreadyVerifiedCaveatIdentifiers.add(ByteBuffer.wrap(identifier));
    }

    void addInvalidDischargeMacaroon(@NotNull Macaroon macaroon) {
        invalidDischargeMacaroons.add(macaroon);
    }

    @NotNull Set<@NotNull Macaroon> filterPossibleDischargeMacaroons(@NotNull Set<@NotNull Macaroon> possibleDischargeMacaroons) {
        return possibleDischargeMacaroons.stream().filter(macaroon -> !invalidDischargeMacaroons.contains(macaroon)).collect(Collectors.toSet());
    }

    private VerificationContext(@NotNull Map<@NotNull String, @NotNull Set<@NotNull String>> membershipConstraints,
                                @NotNull Map<@NotNull String, @NotNull Pair<@NotNull Long, @NotNull Long>> rangeConstraints,
                                @NotNull Set<ByteBuffer> alreadyVerifiedCaveatIdentifiers,
                                @NotNull Set<@NotNull Macaroon> invalidDischargeMacaroons) {
        this.membershipConstraints = membershipConstraints;
        this.rangeConstraints = rangeConstraints;
        this.alreadyVerifiedCaveatIdentifiers = alreadyVerifiedCaveatIdentifiers;
        this.invalidDischargeMacaroons = invalidDischargeMacaroons;
    }

    /**
     * Method to clone the current context.
     * @return  A clone of this context.
     */
    @NotNull public VerificationContext clone() {
        return new VerificationContext(new HashMap<>(membershipConstraints), new HashMap<>(rangeConstraints),
                new HashSet<>(alreadyVerifiedCaveatIdentifiers), new HashSet<>(invalidDischargeMacaroons));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerificationContext that = (VerificationContext) o;
        return membershipConstraints.equals(that.membershipConstraints) && rangeConstraints.equals(that.rangeConstraints) && alreadyVerifiedCaveatIdentifiers.equals(that.alreadyVerifiedCaveatIdentifiers) && invalidDischargeMacaroons.equals(that.invalidDischargeMacaroons);
    }

    @Override
    public int hashCode() {
        return Objects.hash(membershipConstraints, rangeConstraints, alreadyVerifiedCaveatIdentifiers, invalidDischargeMacaroons);
    }
}
