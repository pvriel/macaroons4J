package vrielynckpieterjan.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RangeConstraintFirstPartyCaveat extends FirstPartyCaveat {

    private final static @NotNull Pattern regexPattern = Pattern.compile("(.*) ∈ \\[(.*), (.*)]");

    public RangeConstraintFirstPartyCaveat(@NotNull String rangeUUID, long lowerBound, long upperBound) {
        super(generateCaveatIdentifier(rangeUUID, lowerBound, upperBound));

        if (upperBound < lowerBound) throw new IllegalArgumentException("The given lower bound is greater than the given upper bound.");
    }

    @Override
    protected void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException {
        Pair<String, Pair<Long, Long>> UUIDAndRange = extractRangeUUIDAndBoundsFromCaveatIdentifier();
        String rangeUUID = UUIDAndRange.getLeft();
        Pair<Long, Long> range = UUIDAndRange.getRight();

        context.addRangeConstraint(rangeUUID, range);
    }

    private @NotNull Pair<String, Pair<Long, Long>> extractRangeUUIDAndBoundsFromCaveatIdentifier() {
        String caveatIdentifierAsString = new String(getCaveatIdentifier(), StandardCharsets.UTF_8);

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
