package com.github.pvriel.macaroons4j;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Abstract class representing third-party caveats.
 */
public class ThirdPartyCaveat extends Caveat {

    /**
     * A hint to the locations where this third-party caveat can be discharged.
     */
    private final @NotNull HashSet<@NotNull String> locations;
    /**
     * A byte array, which is originally the root key of the caveat.
     * Once the caveat is added to a Macaroon instance, it is replaced with the verification key.
     */
    private byte[] caveatRootOrVerificationKey;

    /**
     * Constructor for the {@link ThirdPartyCaveat} class.
     * @param   caveatRootKey
     *          The root key of the third-party caveat.
     * @param   caveatIdentifier
     *          The identifier of the caveat.
     * @param   location
     *          A hint to the discharge location.
     */
    public ThirdPartyCaveat(@NotNull String caveatRootKey, final byte[] caveatIdentifier, @NotNull String location) {
        this(caveatRootKey, caveatIdentifier, Set.of(location));
    }

    /**
     * Constructor for the {@link ThirdPartyCaveat} class.
     * @param   caveatRootKey
     *          The root key of the third-party caveat.
     * @param   caveatIdentifier
     *          The identifier of the caveat.
     * @param   locations
     *          A hint to the possible discharge locations.
     */
    public ThirdPartyCaveat(@NotNull String caveatRootKey, final byte[] caveatIdentifier, @NotNull Set<@NotNull String> locations) {
        this(caveatRootKey.getBytes(StandardCharsets.UTF_8), caveatIdentifier, locations);
    }

    /**
     * Constructor for the {@link ThirdPartyCaveat} class.
     * @param   caveatRootKey
     *          The root key of the third-party caveat.
     * @param   caveatIdentifier
     *          The identifier of the caveat.
     * @param   locations
     *          A hint to the possible discharge locations.
     */
    public ThirdPartyCaveat(final byte[] caveatRootKey, final byte[] caveatIdentifier, @NotNull Set<@NotNull String> locations) {
        super(caveatIdentifier);
        this.locations = new HashSet<>(locations);
        this.caveatRootOrVerificationKey = caveatRootKey;
    }

    void setCaveatRootOrVerificationKey(byte[] caveatRootOrVerificationKey) {
        this.caveatRootOrVerificationKey = caveatRootOrVerificationKey;
    }

    /**
     * Method to get the caveat root key.
     * <br>If the caveat is added to a {@link Macaroon} instance, the root key is replaced with the verification key.
     * @return  The caveat root or verification key.
     */
    public byte[] getCaveatRootOrVerificationKey() {
        return caveatRootOrVerificationKey;
    }

    /**
     * Method to get a copy of the target locations.
     * @return  A copy of the target locations.
     */
    @NotNull
    public HashSet<@NotNull String> getCopyOfLocations() {
        return new HashSet<>(locations);
    }

    /**
     * Method to delete a location.
     * <br>This method is not thread-safe.
     * @param   location
     *          The location to delete.
     * @return  The result of the underlying .remove() operation.
     */
    public boolean deleteLocation(@NotNull String location) {
        return locations.remove(location);
    }

    /**
     * Method to add a location.
     * <br>This method is not thread-safe.
     * @param   location
     *          The location to add.
     * @return  The result of the underlying .add() operation.
     */
    public boolean addLocation(@NotNull String location) {
        return locations.add(location);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ThirdPartyCaveat that = (ThirdPartyCaveat) o;
        return locations.equals(that.locations) && Arrays.equals(caveatRootOrVerificationKey, that.caveatRootOrVerificationKey);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), locations);
        result = 31 * result + Arrays.hashCode(caveatRootOrVerificationKey);
        return result;
    }

    @Override
    public String toString() {
        return "ThirdPartyCaveat{id=%s, locations=%s, key=%s}".formatted(getCaveatIdentifier(), locations, caveatRootOrVerificationKey);
    }

    @Override
    public @NotNull ThirdPartyCaveat clone() {
        return new ThirdPartyCaveat(caveatRootOrVerificationKey, getCaveatIdentifier(), getCopyOfLocations());
    }
}
