package vrielynckpieterjan.macaroons4j;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;

public abstract class ThirdPartyCaveat extends Caveat {

    private final @NotNull String location;
    private byte[] caveatRootOrVerificationKey;

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
