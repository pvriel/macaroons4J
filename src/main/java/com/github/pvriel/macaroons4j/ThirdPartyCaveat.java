package com.github.pvriel.macaroons4j;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

/**
 * Abstract class representing third-party caveats.
 */
public class ThirdPartyCaveat extends Caveat {

    /**
     * A hint to the locations where this third-party caveat can be discharged.
     */
    public final @NotNull Set<@NotNull String> locations;
    /**
     * A byte array, which is originally the root key of the caveat.
     * Once the caveat is added to a Macaroon instance, it is replaced with the verification key.
     */
    public byte[] caveatRootOrVerificationKey;

    /**
     * Constructor for the {@link ThirdPartyCaveat} class.
     * @param   caveatRootKey
     *          The root key of the third-party caveat.
     * @param   caveatIdentifier
     *          The identifier of the caveat.
     * @param   location
     *          A hint to the discharge location.
     */
    public ThirdPartyCaveat(String caveatRootKey, byte[] caveatIdentifier, @NotNull String location) {
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
    public ThirdPartyCaveat(String caveatRootKey, byte[] caveatIdentifier, @NotNull Set<@NotNull String> locations) {
        super(caveatIdentifier);
        this.locations = locations;
        this.caveatRootOrVerificationKey = caveatRootKey.getBytes(StandardCharsets.UTF_8);
    }

    void setCaveatRootOrVerificationKey(byte[] caveatRootOrVerificationKey) {
        this.caveatRootOrVerificationKey = caveatRootOrVerificationKey;
    }

    byte[] getCaveatRootOrVerificationKey() {
        return caveatRootOrVerificationKey;
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
}
