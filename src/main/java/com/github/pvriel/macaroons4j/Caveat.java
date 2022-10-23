package com.github.pvriel.macaroons4j;

import java.io.Serializable;
import java.util.Arrays;

/**
 * Abstract class, representing caveats in general.
 * API Note: besides the {@link FirstPartyCaveat} and {@link ThirdPartyCaveat} classes, this class should not have any other child classes.
 */
public abstract class Caveat implements Serializable {

    /**
     * The identifier of the caveat.
     */
    public final byte[] caveatIdentifier;

    /**
     * Constructor of the {@link Caveat} class.
     * @param   caveatIdentifier
     *          The identifier of the caveat.
     */
    protected Caveat(byte[] caveatIdentifier) {
        this.caveatIdentifier = caveatIdentifier;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Caveat caveat = (Caveat) o;
        return Arrays.equals(caveatIdentifier, caveat.caveatIdentifier);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(caveatIdentifier);
    }
}
