package com.github.pvriel.macaroons4j;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Abstract class representing third-party caveats.
 */
public class ThirdPartyCaveat extends Caveat {

    /**
     * A hint to the locations where this third-party caveat can be discharged.
     */
    private final @NotNull Set<@NotNull String> locations;
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
    protected ThirdPartyCaveat(String caveatRootKey, byte[] caveatIdentifier, @NotNull String location) {
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
    protected ThirdPartyCaveat(String caveatRootKey, byte[] caveatIdentifier, @NotNull Set<@NotNull String> locations) {
        super(caveatIdentifier);
        this.locations = locations;
        this.caveatRootOrVerificationKey = caveatRootKey.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Getter for the possible discharge locations for this third-party caveat.
     * @return  A set of strings, which represent the possible discharge locations.
     */
    public @NotNull Set<@NotNull String> getPossibleDischargeLocations() {
        return locations;
    }

    void setCaveatRootOrVerificationKey(byte[] caveatRootOrVerificationKey) {
        this.caveatRootOrVerificationKey = caveatRootOrVerificationKey;
    }

    byte[] getCaveatRootOrVerificationKey() {
        return caveatRootOrVerificationKey;
    }
}
