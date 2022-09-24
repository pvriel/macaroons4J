package com.github.pvriel.macaroons4j;

import java.io.Serializable;

/**
 * Abstract class, representing caveats in general.
 * API Note: besides the {@link FirstPartyCaveat} and {@link ThirdPartyCaveat} classes, this class should not have any other child classes.
 */
abstract class Caveat implements Serializable {

    private final byte[] caveatIdentifier;

    /**
     * Constructor of the {@link Caveat} class.
     * @param   caveatIdentifier
     *          The identifier of the caveat.
     */
    protected Caveat(byte[] caveatIdentifier) {
        this.caveatIdentifier = caveatIdentifier;
    }

    byte[] getCaveatIdentifier() {
        return caveatIdentifier;
    }
}
