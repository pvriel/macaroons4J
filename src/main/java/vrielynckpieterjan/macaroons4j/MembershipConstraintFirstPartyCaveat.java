package vrielynckpieterjan.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MembershipConstraintFirstPartyCaveat extends FirstPartyCaveat {

    private final static @NotNull Pattern regexPattern = Pattern.compile("(.*) ∈ \\[(.*)]");

    public MembershipConstraintFirstPartyCaveat(@NotNull String membershipUUID, @NotNull HashSet<String> requiredMembers) {
        super(generateCaveatIdentifier(membershipUUID, requiredMembers));

        boolean illegalArgument = requiredMembers.stream().anyMatch(element -> element.contains(", "));
        if (illegalArgument) throw new IllegalArgumentException("The given set contains an element which contains the ', ' sequence. This is currently unsupported, however.");
    }

    @Override
    protected void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException {
        Pair<String, Set<String>> UUIDAndRequiredMembers = extractMembershipUUIDAndRequiredMembersFromCaveatIdentifier();
        String membershipUUID = UUIDAndRequiredMembers.getLeft();
        Set<String> requiredMembers = UUIDAndRequiredMembers.getRight();

        context.addMembershipConstraint(membershipUUID, requiredMembers);
    }

    private static byte[] generateCaveatIdentifier(@NotNull String membershipUUID, @NotNull Set<String> requiredMembers) {
        return (membershipUUID + " ∈ " + requiredMembers).getBytes(StandardCharsets.UTF_8);
    }

    private @NotNull Pair<String, Set<String>> extractMembershipUUIDAndRequiredMembersFromCaveatIdentifier() {
        String caveatIdentifierAsString = new String(getCaveatIdentifier(), StandardCharsets.UTF_8);

        Matcher matcher = regexPattern.matcher(caveatIdentifierAsString);
        if (!matcher.matches()) throw new IllegalStateException("The caveat identifier '" + caveatIdentifierAsString + "' does not match the expected format.");
        String membershipUUID = matcher.group(1);

        String requiredMembersAsString = matcher.group(2);
        Set<String> requiredMembers = new HashSet<>(Arrays.asList(requiredMembersAsString.split(", ")));

        return Pair.of(membershipUUID, requiredMembers);
    }
}
