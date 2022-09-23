package vrielynckpieterjan.macaroons4j;

import org.jetbrains.annotations.NotNull;

public abstract class FirstPartyCaveat extends Caveat {

    protected abstract void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException;

    protected FirstPartyCaveat(byte[] caveatIdentifier) {
        super(caveatIdentifier);
    }
}
