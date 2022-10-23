package com.github.pvriel.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class representing range constraints.
 * <br>A range constraint basically represents a UUID and a range, which can be added to a {@link VerificationContext}.
 * <br>After this process, a range constraint with the same UUID is only valid if the range of that range constraint
 * overlap with the already registered range within the verification context.
 * In that case, the overlap becomes the new range for that UUID.
 */
public class RangeConstraintFirstPartyCaveat extends FirstPartyCaveat {

    private final static @NotNull Pattern regexPattern = Pattern.compile("(.*) ∈ \\[(.*), (.*)]");

    /**
     * Constructor for the {@link RangeConstraintFirstPartyCaveat} instance.
     * @param   rangeUUID
     *          The UUID of the range constraint.
     * @param   lowerBound
     *          The lower bound of the range.
     * @param   upperBound
     *          The upper bound of the range.
     * @throws  IllegalArgumentException
     *          If an invalid range (upper bound lower than lower bound) is given.
     */
    public RangeConstraintFirstPartyCaveat(@NotNull String rangeUUID, long lowerBound, long upperBound) throws IllegalArgumentException {
        super(generateCaveatIdentifier(rangeUUID, lowerBound, upperBound));

        if (upperBound < lowerBound) throw new IllegalArgumentException("The given lower bound is greater than the given upper bound.");
    }

    /**
     * @throws  IllegalStateException
     *          If the range defined by this range constraint does not overlap the range (for the same range UUID)
     *          that is already registered within the given verification context.
     */
    @Override
    public void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException {
        Pair<String, Pair<Long, Long>> UUIDAndRange = extractRangeUUIDAndBoundsFromCaveatIdentifier();
        String rangeUUID = UUIDAndRange.getLeft();
        Pair<Long, Long> range = UUIDAndRange.getRight();

        context.addRangeConstraint(rangeUUID, range);
    }

    /**
     * Method to extract the range UUID and the range from the caveat identifier of this range constraint.
     * @return  A pair of the range UUID and the range.
     */
    public @NotNull Pair<@NotNull String, @NotNull Pair<@NotNull Long, @NotNull Long>> extractRangeUUIDAndBoundsFromCaveatIdentifier() {
        String caveatIdentifierAsString = new String(caveatIdentifier, StandardCharsets.UTF_8);

        Matcher matcher = regexPattern.matcher(caveatIdentifierAsString);
        if (!matcher.matches()) throw new IllegalStateException("The caveat identifier '" + caveatIdentifierAsString + "' does not match the expected format.");
        String rangeUUID = matcher.group(1);
        String lowerBoundAsString = matcher.group(2);
        String upperBoundAsString = matcher.group(3);
        long lowerBound = Long.parseLong(lowerBoundAsString);
        long upperBound = Long.parseLong(upperBoundAsString);

        return Pair.of(rangeUUID, Pair.of(lowerBound, upperBound));
    }

    private static byte[] generateCaveatIdentifier(@NotNull String rangeUUID, long lowerBound, long upperBound) {
        return (rangeUUID + " ∈ [" + lowerBound + ", " + upperBound + "]").getBytes();
    }
}
