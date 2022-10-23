package com.github.pvriel.macaroons4j;

import org.jetbrains.annotations.NotNull;

/**
 * Abstract class representing first-party caveats.
 */
public abstract class FirstPartyCaveat extends Caveat {

    /**
     * Method to verify if the first-party caveat holds in a given context.
     * @param   macaroon
     *          The {@link Macaroon} instance that is being diffused, for which this method is being called.
     *          Note that this Macaroon instance does not necessarily represent the Macaroon that contains this first-party caveat.
     * @param   context
     *          The {@link VerificationContext} in which the first-party caveat is being verified.
     * @throws  IllegalStateException
     *          If the first-party caveat can not be verified in the given context.
     */
    public abstract void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException;

    /**
     * Constructor for the {@link FirstPartyCaveat} class.
     * @param   caveatIdentifier
     *          The identifier of the caveat.
     */
    public FirstPartyCaveat(byte[] caveatIdentifier) {
        super(caveatIdentifier);
    }
}
