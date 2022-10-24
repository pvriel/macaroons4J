package com.github.pvriel.macaroons4j;

import org.apache.commons.lang3.tuple.MutableTriple;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

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

    /**
     * Method to verify the Macaroon with a given secret key and an initial context.
     * @param   secretKeyMacaroon
     *          The secret key, which was used to initialize the Macaroon with.
     * @param   verificationContext
     *          An initial {@link VerificationContext}. The initial context can be used to further restrict the validity of the Macaroon during the verification process.
     * @return  A {@link HashSet} of contexts, which represents all the contexts in which the Macaroon instance is valid.
     */
    @NotNull
    public HashSet<VerificationContext> verify(@NotNull String secretKeyMacaroon, @NotNull VerificationContext verificationContext) {
        return verify(new LinkedList<>(List.of(MutableTriple.of(this, calculateMAC(secretKeyMacaroon, macaroonIdentifier), new ArrayList<>(caveats)))),
                new HashSet<>(),
                new HashSet<>(),
                new HashSet<>(Set.of(verificationContext.clone())));
    }

    @NotNull
    private HashSet<VerificationContext> verify(@NotNull List<MutableTriple<Macaroon, String, List<Caveat>>> currentSignaturesWithRemainingCaveats,
                                               @NotNull Set<Macaroon> alreadyVerifiedDischargeMacaroons,
                                               @NotNull Set<Macaroon> invalidDischargeMacaroons,
                                               @NotNull HashSet<VerificationContext> contexts) {
        while (!currentSignaturesWithRemainingCaveats.isEmpty()) {
            // It does not make sense to check the remaining caveats, if there are no remaining contexts in which they can be verified.
            if (contexts.isEmpty()) break;

            // 1. Retrieve the current values to check from the 'stack'.
            MutableTriple<Macaroon, String, List<Caveat>> currentSignatureWithRemainingCaveats = currentSignaturesWithRemainingCaveats.get(0);
            Macaroon currentMacaroon = currentSignatureWithRemainingCaveats.getLeft();
            String currentSignature = currentSignatureWithRemainingCaveats.getMiddle();
            List<Caveat> remainingCaveatsCurrentMacaroon = currentSignatureWithRemainingCaveats.getRight();

            // A) Signature checking.
            if (remainingCaveatsCurrentMacaroon.isEmpty()) {
                if (!(currentMacaroon == this && currentSignature.equals(macaroonSignature)) &&
                    !(bindSignatureForRequest(currentSignature).equals(currentMacaroon.macaroonSignature))) return new HashSet<>();
                else currentSignaturesWithRemainingCaveats.remove(0);
                continue;
            }

            // B) Caveat checking.
            Caveat caveat = remainingCaveatsCurrentMacaroon.remove(0);
            if (caveat instanceof FirstPartyCaveat) {
                // No need for recursive programming here; we can simply filter the contexts and update the signature for A) .
                contexts = verify((FirstPartyCaveat) caveat, contexts);
                currentSignatureWithRemainingCaveats.setMiddle(calculateMAC(currentSignature, caveat.caveatIdentifier));
            } else if (caveat instanceof ThirdPartyCaveat) return verify((ThirdPartyCaveat) caveat, currentSignaturesWithRemainingCaveats,
                    alreadyVerifiedDischargeMacaroons, invalidDischargeMacaroons, contexts);
            else return new HashSet<>(); // Unsupported caveat type.
        }

        System.gc(); // Lot of resources used here.
        return contexts;
    }

    @NotNull
    private HashSet<VerificationContext> verify(@NotNull FirstPartyCaveat firstPartyCaveat, @NotNull HashSet<VerificationContext> verificationContexts) {
        // Only return the contexts in which the first-party caveat hold.
        return verificationContexts.stream().filter(verificationContext -> {
            try {
                firstPartyCaveat.verify(this, verificationContext);
                return true;
            } catch (Exception e) {
                return false;
            }
        }).collect(Collectors.toCollection(HashSet::new));
    }

    @NotNull
    private HashSet<VerificationContext> verify(@NotNull ThirdPartyCaveat thirdPartyCaveat,
                                               @NotNull List<MutableTriple<Macaroon, String, List<Caveat>>> currentSignaturesWithRemainingCaveats,
                                               @NotNull Set<Macaroon> alreadyVerifiedDischargeMacaroons,
                                               @NotNull Set<Macaroon> invalidDischargeMacaroons,
                                               @NotNull HashSet<VerificationContext> contexts) {
        /*
         * 1) Update the signature of the current Macaroon on the stack, which will be checked later on.
         * 2) Calculate the root key of the discharge Macaroon, which we will need to verify the signature of the discharge Macaroon.
         */
        String oldSignatureMacaroon = currentSignaturesWithRemainingCaveats.get(0).getMiddle();
        String rootKeyCaveat;
        try {
            rootKeyCaveat = decrypt(oldSignatureMacaroon, thirdPartyCaveat.getCaveatRootOrVerificationKey());
        } catch (Exception e) {
            return new HashSet<>();
        }
        currentSignaturesWithRemainingCaveats.get(0).setMiddle(calculateMAC(oldSignatureMacaroon, calculateVldCldConcatenationThirdPartyCaveat(thirdPartyCaveat))); // Update the signature of the current Macaroon.

        /*
        Get the discharge Macaroons that can be used to discharge the third-party caveat.
        Already filter the ones of which we know that they'll result in invalid contexts (due to previous discharge tryouts).
         */
        Set<Macaroon> correspondingDischargeMacaroons = boundMacaroons.getOrDefault(ByteBuffer.wrap(thirdPartyCaveat.caveatIdentifier), Set.of())
                .stream().filter(macaroon -> !invalidDischargeMacaroons.contains(macaroon)).collect(Collectors.toSet());
        if (correspondingDischargeMacaroons.stream().anyMatch(alreadyVerifiedDischargeMacaroons::contains))
            return verify(currentSignaturesWithRemainingCaveats, alreadyVerifiedDischargeMacaroons, invalidDischargeMacaroons, contexts); // Same caveat already verified; no need to restrict the contexts further.
        else if (correspondingDischargeMacaroons.isEmpty()) return new HashSet<>(); // Can't discharge the caveat anyways...

        HashSet<VerificationContext> returnValue = new HashSet<>();
        /*
        Discharge the third-party caveat with different discharge Macaroons may finally result in contexts with different restrictions.
        Try ALL of them, and return all the contexts in which the original Macaroon 'can be used' ( == is valid).
         */
        for (Macaroon dischargeMacaroon : correspondingDischargeMacaroons) {
            String initialSignatureDischargeMacaroon = calculateMAC(rootKeyCaveat, dischargeMacaroon.macaroonIdentifier);
            /*
            Notes:
            1) The verification process alters the verification contexts ==> need copies of everything, in case A) the discharge Macaroon can not be used to discharge the third-party caveat, or B) the different discharge Macaroons result in different contexts.
            2) In case of recursive third-party caveats: mark the current caveat as already verified. We still need to check its caveats anyways...
            3) If the discharge process fails for the current discharge Macaroon (resultDischarging.isEmpty()): never use that discharge Macaroon again for the verification process (invalidDischargeMacaroons.add(dischargeMacaroon)).
                Since it could not be used to verify the Macaroon in the current contexts, it can't also be used to verify the Macaroon in equally or more strict contexts.
             */
            List<MutableTriple<Macaroon, String, List<Caveat>>> tempCurrentSignaturesWithRemainingCaveats = new ArrayList<>();
            currentSignaturesWithRemainingCaveats.forEach(triple -> tempCurrentSignaturesWithRemainingCaveats.add(MutableTriple.of(triple.getLeft(), triple.getMiddle(), new ArrayList<>(triple.getRight()))));
            tempCurrentSignaturesWithRemainingCaveats.add(0, MutableTriple.of(dischargeMacaroon, initialSignatureDischargeMacaroon, new ArrayList<>(dischargeMacaroon.caveats)));
            Set<Macaroon> tempAlreadyVerifiedDischargeMacaroons = new HashSet<>(alreadyVerifiedDischargeMacaroons);
            tempAlreadyVerifiedDischargeMacaroons.add(dischargeMacaroon);
            Set<Macaroon> tempInvalidDischargeMacaroons = new HashSet<>(invalidDischargeMacaroons);
            HashSet<VerificationContext> tempContexts = contexts.stream().map(VerificationContext::clone).collect(Collectors.toCollection(HashSet::new));

            HashSet<VerificationContext> resultDischarging = verify(tempCurrentSignaturesWithRemainingCaveats, tempAlreadyVerifiedDischargeMacaroons, tempInvalidDischargeMacaroons, tempContexts);
            if (resultDischarging.isEmpty()) invalidDischargeMacaroons.add(dischargeMacaroon);
            else returnValue.addAll(resultDischarging);
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
