package vrielynckpieterjan.macaroons4j.simple;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.macaroons4j.Macaroon;
import vrielynckpieterjan.macaroons4j.MacaroonTest;

public class SimpleMacaroonTest extends MacaroonTest {
    @Override
    protected @NotNull Macaroon generateMacaroon(@NotNull String secretString, byte[] macaroonIdentifier, @NotNull String hintTargetLocation) {
        return new SimpleMacaroon(secretString, macaroonIdentifier, hintTargetLocation);
    }


}
