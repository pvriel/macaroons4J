package vrielynckpieterjan.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Class representing contexts in which {@link Macaroon} instances can be verified.
 */
public class VerificationContext {

    private final @NotNull Map<@NotNull String, @NotNull Set<@NotNull String>> membershipConstraints;
    private final @NotNull Map<@NotNull String, @NotNull Pair<@NotNull Long, @NotNull Long>> rangeConstraints;

    /**
     * Default constructor for the {@link VerificationContext} class.
     */
    public VerificationContext() {
        this(new HashMap<>(), new HashMap<>());
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
    void addMembershipConstraint(@NotNull String membershipUUID, @NotNull Set<@NotNull String> shouldContainElements) {
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
     */
    void addRangeConstraint(@NotNull String rangeUUID, @NotNull Pair<Long, Long> range) {
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
     * Getter for the membership constraints.
     * @return  The membership constraints.
     */
    public @NotNull Map<@NotNull String, @NotNull Set<@NotNull String>> getMembershipConstraints() {
        return membershipConstraints;
    }

    /**
     * Getter for the range constraints.
     * @return  The range constraints.
     */
    public @NotNull Map<@NotNull String, @NotNull Pair<@NotNull Long, @NotNull Long>> getRangeConstraints() {
        return rangeConstraints;
    }

    private VerificationContext(@NotNull Map<@NotNull String, @NotNull Set<@NotNull String>> membershipConstraints, @NotNull Map<@NotNull String, @NotNull Pair<@NotNull Long, @NotNull Long>> rangeConstraints) {
        this.membershipConstraints = membershipConstraints;
        this.rangeConstraints = rangeConstraints;
    }

    /**
     * Method to clone the current context.
     * @return  A clone of this context.
     */
    @NotNull public VerificationContext clone() {
        return new VerificationContext(new HashMap<>(membershipConstraints), new HashMap<>(rangeConstraints));
    }
}
