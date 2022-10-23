package com.github.pvriel.macaroons4j;

import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.*;

/**
 * Abstract class representing Macaroons.
 * <br>This class already implements the construction, verification, etc. processes, while keeping the
 * encryption, decryption and MAC protocols abstract.
 */
public abstract class Macaroon implements Serializable {

    /**
     * A hint to the target location that issued this Macaroon instance.
     */
    public final @NotNull String hintTargetLocation;
    /**
     * The identifier of the Macaroon.
     */
    public final byte[] macaroonIdentifier;
    /**
     * The caveats of this Macaroon.
     */
    public final @NotNull ArrayList<@NotNull Caveat> caveats;

    /**
     * The signature of the Macaroon.
     */
    public @NotNull String macaroonSignature;
    /**
     * The discharge Macaroons that are bound to this Macaroon instance.
     */
    public final @NotNull HashMap<ByteBuffer, @NotNull Set<@NotNull Macaroon>> boundMacaroons;

    /**
     * Method to generate a MAC value.
     * @param   key
     *          The key for the MAC method.
     * @param   element
     *          The element to MAC with the key.
     * @return
     *          The MAC of the element with the given key, as a String instance.
     */
    protected abstract @NotNull String calculateMAC(@NotNull String key, byte[] element);

    /**
     * Method to symmetrically encrypt an element.
     * Implementation specification: encrypted = encrypt(key, original) iff. original = decrypt(key, encrypted)
     * @param   key
     *          A symmetric key, encoded as a String instance.
     * @param   original
     *          The element to encrypt. The method should be able to encode this as an UTF8 String instance.
     * @return  The element, encrypted with the given key.
     * @throws  Exception
     *          If the element can not be encrypted with the given key.
     */
    public abstract byte[] encrypt(@NotNull String key, byte[] original) throws Exception;

    /**
     * Method to symmetrically decrypt an encrypted element.
     * Implementation specification: encrypted = encrypt(key, original) iff. original = decrypt(key, encrypted)
     * @param   key
     *          The key to decrypt the encrypted element with, encoded as a String instance.
     * @param   encrypted
     *          The encrypted element.
     * @return  The decrypted element, as an UTF8 String instance.
     * @throws  Exception
     *          If the element can not be decrypted using the given key.
     */
    public abstract @NotNull String decrypt(@NotNull String key, byte[] encrypted) throws Exception;

    /**
     * Method to bind the signature of a discharge Macaroon to the current Macaroon instance.
     * @param   originalSignature
     *          The current value of the signature of the discharge Macaroon, as a String instance.
     * @return  The new (bound) signature of the discharge Macaroon, as a String instance.
     */
    protected abstract @NotNull String bindSignatureForRequest(@NotNull String originalSignature);

    /**
     * Constructor for the {@link Macaroon} class.
     * @param   secretString
     *          The secret value of the Macaroon, which is required to both generate and verify the signature of the Macaroon instance.
     * @param   macaroonIdentifier
     *          The public identifier of the Macaroon instance.
     * @param   hintTargetLocation
     *          A hint to the target location (which typically issues the Macaroon instance).
     */
    public Macaroon(@NotNull String secretString, byte[] macaroonIdentifier, @NotNull String hintTargetLocation) {
        this(hintTargetLocation, macaroonIdentifier, new LinkedList<>(), "", new HashMap<>()); // "": temporary value
        this.macaroonSignature = calculateMAC(secretString, macaroonIdentifier);
    }

    /**
     * Constructor for the {@link Macaroon} class.
     * @param   hintTargetLocation
     *          A hint to the target location (which typically issues the Macaroon instance).
     * @param   macaroonIdentifier
     *          The public identifier of the Macaroon instance.
     * @param   caveats
     *          The caveats of the Macaroon instance.
     * @param   macaroonSignature
     *          The signature of the Macaroon instance.
     * @param   boundMacaroons
     *          The discharge Macaroons that are bound to this Macaroon instance.
     */
    protected Macaroon(@NotNull String hintTargetLocation, byte[] macaroonIdentifier, @NotNull List<@NotNull Caveat> caveats,
                     @NotNull String macaroonSignature, @NotNull Map<ByteBuffer, @NotNull Set<@NotNull Macaroon>> boundMacaroons) {
        this.hintTargetLocation = hintTargetLocation;
        this.macaroonIdentifier = macaroonIdentifier;
        this.caveats = new ArrayList<>(caveats);
        this.macaroonSignature = macaroonSignature;
        this.boundMacaroons = new HashMap<>(boundMacaroons);
    }

    private void addCaveat(@NotNull Caveat caveat, byte[] toMac) {
        this.caveats.add(caveat);
        this.macaroonSignature = calculateMAC(this.macaroonSignature, toMac);
    }

    /**
     * Method to add a first-party caveat to, and update the signature of the Macaroon instance.
     * After calling this method, the given {@link FirstPartyCaveat} instance is owned by this Macaroon instance.
     * <br>This also means that a caveat can NOT be added multiple times to the Macaroon.
     * Instead, each time, a new Macaroon instance should be generated.
     * @param   caveat
     *          The {@link FirstPartyCaveat} to add to the Macaroon instance.
     */
    public void addCaveat(@NotNull FirstPartyCaveat caveat) {
        addCaveat(caveat, caveat.caveatIdentifier);
    }

    /**
     * Method to add a third-party caveat to, and update the signature of the Macaroon instance.
     * After calling this method, the given {@link ThirdPartyCaveat} instance is owned by this Macaroon instance.
     * @param   caveat
     *          The {@link ThirdPartyCaveat} to add to the Macaroon instance.
     * @throws  Exception
     *          If the third-party caveat can not be added to the Macaroon instance.
     */
    public void addCaveat(@NotNull ThirdPartyCaveat caveat) throws Exception {
        caveat.setCaveatRootOrVerificationKey(encrypt(this.macaroonSignature, caveat.getCaveatRootOrVerificationKey()));
        byte[] toMAC = calculateVldCldConcatenationThirdPartyCaveat(caveat);
        addCaveat(caveat, toMAC);
    }

    /**
     * Method to bind a discharge Macaroon to this Macaroon instance, as preparation for a request.
     * After calling this method, the given discharge Macaroon is owned by this Macaroon instance.
     * @param   dischargeMacaroon
     *          Another Macaroon instance, which will be bound to this Macaroon instance.
     * @throws  IllegalArgumentException
     *          If the discharge Macaroons has bound discharge Macaroons; these should be bound to this Macaroon instance instead.
     */
    public void bindMacaroonForRequest(@NotNull Macaroon dischargeMacaroon) {
        if (!dischargeMacaroon.boundMacaroons.isEmpty()) {
            throw new IllegalArgumentException("Discharge Macaroon has bound discharge Macaroons; these should be bound to this Macaroon instance instead.");
        }

        dischargeMacaroon.macaroonSignature = bindSignatureForRequest(dischargeMacaroon.macaroonSignature);

        if (!boundMacaroons.containsKey(ByteBuffer.wrap(dischargeMacaroon.macaroonIdentifier))) {
            boundMacaroons.put(ByteBuffer.wrap(dischargeMacaroon.macaroonIdentifier), new HashSet<>());
        }
        Set<Macaroon> boundMacaroonsForIdentifierDischargeMacaroon = boundMacaroons.get(ByteBuffer.wrap(dischargeMacaroon.macaroonIdentifier));
        boundMacaroonsForIdentifierDischargeMacaroon.add(dischargeMacaroon);
    }

    private byte[] calculateVldCldConcatenationThirdPartyCaveat(@NotNull ThirdPartyCaveat caveat) {
        // No cache mechanism here; I don't think it would improve the performance of this method?
        byte[] toMAC = new byte[caveat.getCaveatRootOrVerificationKey().length + caveat.caveatIdentifier.length];
        System.arraycopy(caveat.getCaveatRootOrVerificationKey(), 0, toMAC, 0, caveat.getCaveatRootOrVerificationKey().length);
        System.arraycopy(caveat.caveatIdentifier, 0, toMAC, caveat.getCaveatRootOrVerificationKey().length, caveat.caveatIdentifier.length);
        return toMAC;
    }

    @NotNull
    public HashSet<VerificationContext> verify(@NotNull String secretKeyMacaroon, @NotNull VerificationContext initialContext) {
        String initialSignature = calculateMAC(secretKeyMacaroon, macaroonIdentifier);
        HashSet<VerificationContext> holdingContexts = new HashSet<>();
        holdingContexts.add(initialContext.clone());
        HashSet<Macaroon> alreadyVerifiedMacaroons = new HashSet<>();
        alreadyVerifiedMacaroons.add(this);
        HashSet<Macaroon> alreadyVerifiedInvalidMacaroons = new HashSet<>();

        return verify(initialSignature, this, holdingContexts, alreadyVerifiedMacaroons, alreadyVerifiedInvalidMacaroons);
    }

    @NotNull
    private HashSet<VerificationContext> verify(@NotNull String currentSignature, @NotNull Macaroon currentMacaroon,
                                                @NotNull HashSet<VerificationContext> holdingContexts,
                                                @NotNull Set<Macaroon> alreadyVerifiedMacaroons,
                                                @NotNull Set<Macaroon> alreadyVerifiedInvalidMacaroons) {
        HashSet<VerificationContext> tempContexts;
        for (Caveat caveat : currentMacaroon.caveats) {

            if (caveat instanceof FirstPartyCaveat) {
                tempContexts = verify((FirstPartyCaveat) caveat, holdingContexts);
                currentSignature = calculateMAC(currentSignature, caveat.caveatIdentifier);
            } else if (caveat instanceof ThirdPartyCaveat) {
                tempContexts = verify(currentSignature, (ThirdPartyCaveat) caveat, holdingContexts, alreadyVerifiedMacaroons, alreadyVerifiedInvalidMacaroons);
                currentSignature = calculateMAC(currentSignature, calculateVldCldConcatenationThirdPartyCaveat((ThirdPartyCaveat) caveat));
            } else {
                // Unsupported caveat subtype.
                return new HashSet<>();
            }

            if (tempContexts.isEmpty()) return tempContexts;
            holdingContexts = tempContexts;
        }

        if (!(currentMacaroon == this && currentSignature.equals(currentMacaroon.macaroonSignature)) &&
                !(currentSignature.equals(bindSignatureForRequest(currentMacaroon.macaroonSignature))))
            holdingContexts.clear();

        return holdingContexts;
    }

    @NotNull
    private HashSet<VerificationContext> verify(@NotNull FirstPartyCaveat firstPartyCaveat, @NotNull Set<VerificationContext> holdingContexts) {
        HashSet<VerificationContext> returnValue = new HashSet<>();
        for (VerificationContext context : holdingContexts) {
            try {
                // Does not matter if the contexts are updated here; the invalid ones are thrown away anyways...
                firstPartyCaveat.verify(this, context);
                returnValue.add(context);
            } catch (Exception ignored) {}
        }
        return returnValue;
    }

    @NotNull
    private HashSet<VerificationContext> verify(@NotNull String currentSignatureMacaroon,
                                                @NotNull ThirdPartyCaveat thirdPartyCaveat,
                                                @NotNull HashSet<VerificationContext> holdingContexts,
                                                @NotNull Set<Macaroon> alreadyVerifiedMacaroons,
                                                @NotNull Set<Macaroon> alreadyVerifiedInvalidMacaroons) {

        String caveatRootKey;
        try {
            caveatRootKey = decrypt(currentSignatureMacaroon, thirdPartyCaveat.caveatRootOrVerificationKey);
        } catch (Exception e) {
            return new HashSet<>();
        }

        Set<Macaroon> relevantDischargeMacaroons = new HashSet<>(boundMacaroons
                .getOrDefault(ByteBuffer.wrap(thirdPartyCaveat.caveatIdentifier), Set.of()));
        relevantDischargeMacaroons.removeAll(alreadyVerifiedInvalidMacaroons);
        if (relevantDischargeMacaroons.stream().anyMatch(alreadyVerifiedMacaroons::contains)) return holdingContexts;

        HashSet<VerificationContext> returnValue = new HashSet<>();
        for (Macaroon dischargeMacaroon : relevantDischargeMacaroons) {
            HashSet<Macaroon> alreadyVerifiedMacaroonsForDischargeMacaroon = new HashSet<>(alreadyVerifiedMacaroons);
            alreadyVerifiedMacaroonsForDischargeMacaroon.add(dischargeMacaroon);
            try {
                returnValue.addAll(verify(caveatRootKey, dischargeMacaroon, new HashSet<>(holdingContexts), alreadyVerifiedMacaroonsForDischargeMacaroon,
                        new HashSet<>(alreadyVerifiedInvalidMacaroons)));
            } catch (Exception e) {
                alreadyVerifiedInvalidMacaroons.add(dischargeMacaroon);
            }
        }
        return returnValue;
    }

    /**
     * Method to clone the Macaroon instance.
     * @return  A clone of this Macaroon instance.
     */
    public abstract @NotNull Macaroon clone();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Macaroon macaroon = (Macaroon) o;
        return hintTargetLocation.equals(macaroon.hintTargetLocation) && Arrays.equals(macaroonIdentifier, macaroon.macaroonIdentifier) && caveats.equals(macaroon.caveats) && macaroonSignature.equals(macaroon.macaroonSignature) && boundMacaroons.equals(macaroon.boundMacaroons);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(hintTargetLocation, caveats, macaroonSignature, boundMacaroons);
        result = 31 * result + Arrays.hashCode(macaroonIdentifier);
        return result;
    }
}
