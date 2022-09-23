package vrielynckpieterjan.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

// TODO: remove abstract and make sure all the methods are implemented.
public class VerificationContext {

    private final Map<String, Set<String>> membershipConstraints;
    private final Map<String, Pair<Long, Long>> rangeConstraints;

    public VerificationContext() {
        this(new HashMap<>(), new HashMap<>());
    }

    void addMembershipConstraint(@NotNull String membershipUUID, @NotNull Set<String> shouldContainElements) {
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

    public Map<String, Set<String>> getMembershipConstraints() {
        return membershipConstraints;
    }

    public Map<String, Pair<Long, Long>> getRangeConstraints() {
        return rangeConstraints;
    }

    private VerificationContext(Map<String, Set<String>> membershipConstraints, Map<String, Pair<Long, Long>> rangeConstraints) {
        this.membershipConstraints = membershipConstraints;
        this.rangeConstraints = rangeConstraints;
    }

    @NotNull protected VerificationContext clone() {
        return new VerificationContext(new HashMap<>(membershipConstraints), new HashMap<>(rangeConstraints));
    }
}
