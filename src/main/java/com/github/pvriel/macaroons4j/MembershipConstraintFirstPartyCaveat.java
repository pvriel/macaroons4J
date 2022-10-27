package com.github.pvriel.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class representing membership constraints.
 * <br>A membership constraint basically represents a UUID and a set, which can be added to a {@link VerificationContext}.
 * <br>After this process, a membership constraint with the same UUID is only valid if the set of the membership constraint
 * is a (sub-)set of the set that is already registered within the verification context.
 */
public class MembershipConstraintFirstPartyCaveat extends FirstPartyCaveat {

    private final static @NotNull Pattern regexPattern = Pattern.compile("(.*) ∈ \\[(.*)]");

    /**
     * Constructor for the {@link MembershipConstraintFirstPartyCaveat} class.
     * @param   membershipUUID
     *          The UUID of the membership constraint.
     * @param   requiredMembers
     *          The elements that should be present for the membership UUID, in order for the membership constraint to be valid.
     * @throws  IllegalArgumentException
     *          If any element contains the ', ' char sequence. This is not supported at the moment.
     */
    public MembershipConstraintFirstPartyCaveat(@NotNull String membershipUUID, @NotNull HashSet<String> requiredMembers) throws IllegalArgumentException {
        super(generateCaveatIdentifier(membershipUUID, requiredMembers));

        boolean illegalArgument = requiredMembers.stream().anyMatch(element -> element.contains(", "));
        if (illegalArgument) throw new IllegalArgumentException("The given set contains an element which contains the ', ' sequence. This is currently unsupported, however.");
    }

    /**
     * @throws  IllegalStateException
     *          If the members from this membership constraint don't represent a subset of the members that are already
     *          stored as part of the verification context.
     */
    @Override
    public void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException {
        Pair<String, Set<String>> UUIDAndRequiredMembers = extractMembershipUUIDAndRequiredMembersFromCaveatIdentifier();
        String membershipUUID = UUIDAndRequiredMembers.getLeft();
        Set<String> requiredMembers = UUIDAndRequiredMembers.getRight();

        context.addMembershipConstraint(membershipUUID, requiredMembers);
    }

    private static byte[] generateCaveatIdentifier(@NotNull String membershipUUID, @NotNull Set<@NotNull String> requiredMembers) {
        return (membershipUUID + " ∈ " + requiredMembers).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Method to extract the membership UUID and the required members from the caveat identifier.
     * @return A pair, where the left element is the membership UUID and the right element is the set of required members.
     */
    public @NotNull Pair<@NotNull String, @NotNull Set<@NotNull String>> extractMembershipUUIDAndRequiredMembersFromCaveatIdentifier() {
        String caveatIdentifierAsString = new String(getCaveatIdentifier(), StandardCharsets.UTF_8);

        Matcher matcher = regexPattern.matcher(caveatIdentifierAsString);
        if (!matcher.matches()) throw new IllegalStateException("The caveat identifier '" + caveatIdentifierAsString + "' does not match the expected format.");
        String membershipUUID = matcher.group(1);

        String requiredMembersAsString = matcher.group(2);
        Set<String> requiredMembers = new HashSet<>(Arrays.asList(requiredMembersAsString.split(", ")));

        return Pair.of(membershipUUID, requiredMembers);
    }

    @Override
    public @NotNull MembershipConstraintFirstPartyCaveat clone() {
        var extractedInfo = extractMembershipUUIDAndRequiredMembersFromCaveatIdentifier();
        return new MembershipConstraintFirstPartyCaveat(extractedInfo.getLeft(), new HashSet<>(extractedInfo.getRight()));
    }

    @Override
    @NotNull
    public String toString() {
        var extracted = extractMembershipUUIDAndRequiredMembersFromCaveatIdentifier();
        return "MembershipConstraintFirstPartyCaveat{%s ∈ %s}".formatted(extracted.getLeft(), extracted.getRight());
    }
}
