package com.github.pvriel.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.util.*;

/**
 * Class representing contexts in which {@link Macaroon} instances can be verified.
 */
public class VerificationContext {

    /**
     * Map representing the membership constraints, mapping their UUIDs to the elements of the membership.
     */
    private final @NotNull HashMap<@NotNull String, @NotNull Set<@NotNull String>> membershipConstraints;
    /**
     * Map representing the range constraints, mapping their UUIDs to the range.
     */
    private final @NotNull HashMap<@NotNull String, @NotNull Pair<@NotNull Long, @NotNull Long>> rangeConstraints;

    /**
     * Default constructor for the {@link VerificationContext} class.
     */
    public VerificationContext() {
        this(new HashMap<>(), new HashMap<>());
    }

    /**
     * Method to get a copy of the currently holding membership constraints.
     * <br>This method is not thread-safe.
     * @return  The currently holding membership constraints.
     */
    @NotNull
    public HashMap<@NotNull String, @NotNull Set<@NotNull String>> getCopyOfMembershipConstraints() {
        HashMap<String, Set<String>> returnValue = new HashMap<>();
        for (String membershipUUID : membershipConstraints.keySet()) returnValue.put(membershipUUID, getCopyOfMembershipConstraint(membershipUUID));
        return returnValue;
    }

    /**
     * Method to get a copy of a currently holding membership constraint.
     * <br>This method is not thread-safe.
     * @param   membershipConstraintUUID
     *          The UUID of the membership constraint to copy from the context.
     * @return  A copy of the members from the membership constraint.
     */
    @NotNull
    public HashSet<@NotNull String> getCopyOfMembershipConstraint(@NotNull String membershipConstraintUUID) {
        return new HashSet<>(membershipConstraints.getOrDefault(membershipConstraintUUID, new HashSet<>()));
    }

    /**
     * Method to get a copy of the currently holding range constraints.
     * <br>This method is not thread-safe.
     * @return  The currently holding membership constraints.
     */
    @NotNull
    public HashMap<@NotNull String, @NotNull Pair<@NotNull Long, @NotNull Long>> getCopyOfRangeConstraints() {
        HashMap<String, Pair<Long, Long>> returnValue = new HashMap<>();
        for (String rangeConstraintUUID : rangeConstraints.keySet()) returnValue.put(rangeConstraintUUID, getCopyOfRangeConstraint(rangeConstraintUUID));
        return returnValue;
    }

    /**
     * Method to get a copy of a currently holding range constraint.
     * <br>This method is not thread-safe.
     * @param rangeConstraintUUID
     *        The UUID of the range constraint to copy from the context.
     * @return  A copy of the range from the constraint.
     */
    @NotNull
    public Pair<@NotNull Long, @NotNull Long> getCopyOfRangeConstraint(@NotNull String rangeConstraintUUID) {
        var oldPair = rangeConstraints.getOrDefault(rangeConstraintUUID, Pair.of(Long.MIN_VALUE, Long.MAX_VALUE));
        return Pair.of(oldPair.getLeft(), oldPair.getRight());
    }

    /**
     * Method to get a copy of the currently holding membership constraints UUIDs.
     * @return  The copy.
     */
    @NotNull
    HashSet<@NotNull String> getCopyOfMembershipConstraintUUIDs() {
        return new HashSet<>(membershipConstraints.keySet());
    }

    /**
     * Method to get a copy of the currently holding range constraints UUIDs.
     * @return  The copy.
     */
    @NotNull
    HashSet<@NotNull String> getCopyOfRangeConstraintUUIDs() {
        return new HashSet<>(rangeConstraints.keySet());
    }

    /**
     * Method to remove an existing membership constraint based on its UUID.
     * <br>This method is not thread-safe.
     * @param   membershipConstraintUUID
     *          The UUID of the membership constraint.
     * @return  The removed membership constraint.
     */
    @NotNull
    public Set<@NotNull String> removeMembershipConstraint(@NotNull String membershipConstraintUUID) {
        return membershipConstraints.remove(membershipConstraintUUID);
    }

    /**
     * Method to remove an existing range constraint based on its UUID.
     * <br>This method is not thread-safe.
     * @param   rangeConstraintUUID
     *          The UUID of the range constraint.
     * @return  The removed range constraint.
     */
    @NotNull
    public Pair<@NotNull Long, @NotNull Long> removeRangeConstraint(@NotNull String rangeConstraintUUID) {
        return rangeConstraints.remove(rangeConstraintUUID);
    }



    /**
     * Method to add a membership constraint to the verification context.
     * <br>If the method is called for a first time for a specific membership UUID, the membership is just set to the given elements.
     * <br>If the method is called again for a specific membership UUID, the membership is only updated if the given set is a (sub-)set
     * of the set that was used to call the method the previous time. Otherwise, this method throws an {@link IllegalStateException}.
     * <br> This method is not thread-safe.
     * @param   membershipUUID
     *          The UUID of the membership.
     * @param   shouldContainElements
     *          The elements that should be included in the membership.
     */
    public void addMembershipConstraint(@NotNull String membershipUUID, @NotNull Set<@NotNull String> shouldContainElements) throws IllegalStateException {
        Set<String> copyOfShouldContainElements = new HashSet<>(shouldContainElements);
        if (!membershipConstraints.containsKey(membershipUUID)) {
            membershipConstraints.put(membershipUUID, copyOfShouldContainElements);
            return;
        }

        Set<String> existingElements = membershipConstraints.get(membershipUUID);
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
     * <br> This method is not thread-safe.
     * @param   rangeUUID
     *          The UUID of the range.
     * @param   range
     *          The new range.
     * @throws  IllegalStateException
     *          If a range has already been defined for the given UUID, but it does not overlap with the given range of this method invocation.
     */
    public void addRangeConstraint(@NotNull String rangeUUID, @NotNull Pair<@NotNull Long, @NotNull Long> range) throws IllegalStateException {
        addRangeConstraint(rangeUUID, range.getLeft(), range.getRight());
    }

    /**
     * Method to add a range constraint to the verification context.
     * <br>If the method is called for a first time for a specific range UUID, the range is just set.
     * <br>If the method is called again for a specific range UUID, the range is only updated to the overlap, if the given range overlaps
     * with the current range. Otherwise, this method throws an {@link IllegalStateException}.
     * <br> This method is not thread-safe.
     * @param   rangeUUID
     *          The UUID of the range.
     * @param   startNewRange
     *          The lower bound of the range.
     * @param   endNewRange
     *          The upper bound of the range.
     * @throws  IllegalStateException
     *          If a range has already been defined for the given UUID, but it does not overlap with the given range of this method invocation.
     */
    public void addRangeConstraint(@NotNull String rangeUUID, long startNewRange, long endNewRange) throws IllegalStateException {
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
            rangeConstraints.put(rangeUUID, Pair.of(startNewRange, endNewRange));
        }
    }

    protected VerificationContext(@NotNull Map<@NotNull String, @NotNull Set<@NotNull String>> membershipConstraints,
                                @NotNull Map<@NotNull String, @NotNull Pair<@NotNull Long, @NotNull Long>> rangeConstraints) {
        this.membershipConstraints = new HashMap<>(membershipConstraints);
        this.rangeConstraints = new HashMap<>(rangeConstraints);
    }

    /**
     * Method to clone the current context.
     * @return  A clone of this context.
     */
    @NotNull public VerificationContext clone() {
        return new VerificationContext(membershipConstraints, rangeConstraints);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerificationContext that = (VerificationContext) o;
        return membershipConstraints.equals(that.membershipConstraints) && rangeConstraints.equals(that.rangeConstraints);
    }

    @Override
    public int hashCode() {
        return Objects.hash(membershipConstraints, rangeConstraints);
    }

    @NotNull
    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder("VerificationContext{");
        for (var rangeConstraintEntry : rangeConstraints.entrySet()) stringBuilder.append("%s ∈ [%d, %d], ".formatted(rangeConstraintEntry.getKey(), rangeConstraintEntry.getValue().getLeft(), rangeConstraintEntry.getValue().getRight()));
        for (var membershipConstraintEntry : membershipConstraints.entrySet()) stringBuilder.append("%s ∈ %s, ".formatted(membershipConstraintEntry.getKey(), membershipConstraintEntry.getValue()));
        if (rangeConstraints.size() > 0 || membershipConstraints.size() > 0) stringBuilder.delete(stringBuilder.length() - 2, stringBuilder.length());
        stringBuilder.append("}");
        return stringBuilder.toString();
    }
}
