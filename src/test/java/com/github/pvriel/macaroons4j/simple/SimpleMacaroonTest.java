package com.github.pvriel.macaroons4j.simple;

import org.jetbrains.annotations.NotNull;
import com.github.pvriel.macaroons4j.Macaroon;
import com.github.pvriel.macaroons4j.MacaroonTest;

public class SimpleMacaroonTest extends MacaroonTest {
    @Override
    protected @NotNull Macaroon generateMacaroon(@NotNull String secretString, byte[] macaroonIdentifier, @NotNull String hintTargetLocation) {
        return new SimpleMacaroon(secretString, macaroonIdentifier, hintTargetLocation);
    }


}
