package com.github.pvriel.macaroons4j.simple;

import com.github.pvriel.macaroons4j.Macaroon;
import com.github.pvriel.macaroons4j.MacaroonTest;
import org.jetbrains.annotations.NotNull;

public class SimpleMacaroonTest extends MacaroonTest {
    @Override
    protected @NotNull Macaroon generateMacaroon(@NotNull String secretString, byte[] macaroonIdentifier, @NotNull String hintTargetLocation) {
        return new SimpleMacaroon(secretString, macaroonIdentifier, hintTargetLocation);
    }


}
