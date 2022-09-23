package vrielynckpieterjan.macaroons4j;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;

/**
 * Abstract class representing third-party caveats.
 */
public abstract class ThirdPartyCaveat extends Caveat {

    private final @NotNull String location;
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
        super(caveatIdentifier);
        this.location = location;
        this.caveatRootOrVerificationKey = caveatRootKey.getBytes(StandardCharsets.UTF_8);
    }

    void setCaveatRootOrVerificationKey(byte[] caveatRootOrVerificationKey) {
        this.caveatRootOrVerificationKey = caveatRootOrVerificationKey;
    }

    byte[] getCaveatRootOrVerificationKey() {
        return caveatRootOrVerificationKey;
    }
}
