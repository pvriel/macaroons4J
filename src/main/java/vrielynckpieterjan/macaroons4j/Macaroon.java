package vrielynckpieterjan.macaroons4j;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.util.*;

/**
 * Abstract class representing Macaroons.
 * <br>This class already implements the construction, verification, etc. processes, while keeping the
 * encryption, decryption and MAC protocols abstract.
 */
public abstract class Macaroon implements Serializable {

    private final @NotNull String hintTargetLocation;
    private final byte[] macaroonIdentifier;
    private final @NotNull List<@NotNull Caveat> caveats = new LinkedList<>();
    // Is set to protected for testing purposes: don't actually change this!
    protected @NotNull String macaroonSignature;
    private final @NotNull Map<byte[], @NotNull Set<@NotNull Macaroon>> boundMacaroons = new HashMap<>();

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
    protected abstract byte[] encrypt(@NotNull String key, byte[] original) throws Exception;

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
    protected abstract @NotNull String decrypt(@NotNull String key, byte[] encrypted) throws Exception;

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
        this.hintTargetLocation = hintTargetLocation;
        this.macaroonIdentifier = macaroonIdentifier;
        this.macaroonSignature = calculateMAC(secretString, macaroonIdentifier);
    }

    private void addCaveat(@NotNull Caveat caveat, byte[] toMac) {
        this.caveats.add(caveat);
        this.macaroonSignature = calculateMAC(this.macaroonSignature, toMac);
    }

    /**
     * Method to add a first-party caveat to, and update the signature of the Macaroon instance.
     * After calling this method, the given {@link FirstPartyCaveat} instance is owned by this Macaroon instance.
     * @param   caveat
     *          The {@link FirstPartyCaveat} to add to the Macaroon instance.
     */
    public void addCaveat(@NotNull FirstPartyCaveat caveat) {
        addCaveat(caveat, caveat.getCaveatIdentifier());
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
     */
    public void bindMacaroonForRequest(@NotNull Macaroon dischargeMacaroon) {
        dischargeMacaroon.macaroonSignature = bindSignatureForRequest(dischargeMacaroon.macaroonSignature);

        if (!boundMacaroons.containsKey(dischargeMacaroon.macaroonIdentifier)) {
            boundMacaroons.put(dischargeMacaroon.macaroonIdentifier, new HashSet<>());
        }
        Set<Macaroon> boundMacaroonsForIdentifierDischargeMacaroon = boundMacaroons.get(dischargeMacaroon.macaroonIdentifier);
        boundMacaroonsForIdentifierDischargeMacaroon.add(dischargeMacaroon);
    }

    /**
     * Method to verify if a Macaroon is valid in a given context.
     * @param   secretString
     *          The secret value of the Macaroon, which is required to both generate and verify the signature of the Macaroon instance.
     * @param   context
     *          The {@link VerificationContext}, in which the caveats of this Macaroon instance should hold in order to pass the verification process.
     * @throws  Exception
     *          If the verification process failed due to:
     *          <br>A) tampering with the signatures and/or caveats,
     *          <br>B) the presence of discharge Macaroons that are bound to other discharge Macaroons, instead of this Macaroon instance,
     *          <br>C) providing the wrong secret value of the Macaroon, or
     *          <br>D) the constraints of the caveats resulting in an impossible context.
     * @return  An equally or more strict verification context compared to the given {@link VerificationContext} instance,
     *          in which the constraints from the caveats of this Macaroon instance also hold.
     *          <br>The caveats are discharged and verified in a depth-first manner / in order.
     *          If there are multiple resulting verification contexts possible, only the first one will be returned.
     */
    public @NotNull VerificationContext verify(@NotNull String secretString, @NotNull VerificationContext context) throws Exception {
        // 1. Make sure that all discharge macaroons are only bound to this macaroon, and not to other discharge macaroons.
        for (Set<Macaroon> boundMacaroonsForIdentifier : boundMacaroons.values()) {
            for (Macaroon boundMacaroon : boundMacaroonsForIdentifier) {
                if (boundMacaroon.boundMacaroons.size() > 0) {
                    throw new IllegalStateException("Discharge macaroons should only be bound to the macaroon that is being verified; " +
                            "however, at least one discharge macaroon is bound to discharge macaroon (%s).".formatted(boundMacaroon));
                }
            }
        }
        /*
        2. Find a collection of discharge macaroons that are bound to this macaroon, that are valid in the context and that are sufficient to reconstruct the signature of the macaroon.
         */
        String signatureSoFar = calculateMAC(secretString, macaroonIdentifier);
        List<Caveat> remainingCaveatsToVerifyInContext = new LinkedList<>(caveats);
        Pair<String, VerificationContext> signatureWithContext = verify(signatureSoFar, remainingCaveatsToVerifyInContext, context);
        signatureSoFar = signatureWithContext.getLeft();
        VerificationContext validVerificationContext = signatureWithContext.getRight();
        if (!signatureSoFar.equals(macaroonSignature)) {
            throw new IllegalStateException("The signature of the macaroon is not valid: the signature of the macaroon is %s, but the signature that was reconstructed is %s.".formatted(macaroonSignature, signatureSoFar));
        }
        return validVerificationContext;
    }

    private @NotNull Pair<@NotNull String, @NotNull VerificationContext> verify(@NotNull String signatureSoFar, @NotNull List<Caveat> remainingCaveatsToVerifyInContext, @NotNull VerificationContext context) throws Exception {
        while (!remainingCaveatsToVerifyInContext.isEmpty()) {
            Caveat caveat = remainingCaveatsToVerifyInContext.remove(0);
            if (caveat instanceof FirstPartyCaveat) {
                signatureSoFar = verify(signatureSoFar, (FirstPartyCaveat) caveat, context);
            } else if (caveat instanceof ThirdPartyCaveat) {
                return verify(signatureSoFar, (ThirdPartyCaveat) caveat, remainingCaveatsToVerifyInContext, context);
            } else {
                throw new IllegalStateException("Found a caveat (%s) that is neither a first- or third-party caveat.".formatted(caveat)); // This should never happen.
            }
        }

        return Pair.of(signatureSoFar, context);
    }

    private @NotNull String verify(@NotNull String signatureSoFar, @NotNull FirstPartyCaveat caveat, @NotNull VerificationContext context) throws IllegalStateException {
        caveat.verify(this, context);
        return calculateMAC(signatureSoFar, caveat.getCaveatIdentifier());
    }

    private @NotNull Pair<@NotNull String, @NotNull VerificationContext> verify(@NotNull String signatureSoFar, @NotNull ThirdPartyCaveat caveat,
                                @NotNull List<Caveat> remainingCaveatsToVerifyInContext,
                                @NotNull VerificationContext context) throws Exception {
        // 1. Extract the caveat root String from the verification String, and calculate the initial signature for the discharge macaroon.
        String caveatRootString = decrypt(signatureSoFar, caveat.getCaveatRootOrVerificationKey());
        String signatureSoFarForDischargeMacaroon = calculateMAC(caveatRootString, caveat.getCaveatIdentifier());

        /*
            2. Check for a bound discharge macaroon that can be used to discharge the current third-party caveat, and make sure the signature of that discharge macaroon is correct.
            At least one discharge macaroon should work in order for this macaroon to be able to get verified.

            Since the verification process for a third-party caveat may alter the VerificationContext, each possible discharge macaroon should work with its own VerificationContext.
            However, if there's only one possible discharge macaroon for the caveat, we can just pass that one.
         */
        Set<Macaroon> correspondingDischargeMacaroons = boundMacaroons.get(caveat.getCaveatIdentifier());
        if (correspondingDischargeMacaroons == null || correspondingDischargeMacaroons.isEmpty()) {
            throw new IllegalStateException("No bound discharge macaroons found for third-party caveat (%s).".formatted(caveat));
        }
        for (Macaroon possibleDischargeMacaroon: correspondingDischargeMacaroons) {
            try {
                VerificationContext contextForVerificationDischargeMacaroon = (correspondingDischargeMacaroons.size() == 1)? context : context.clone();
                Pair<String, VerificationContext> resultingDischargeMacaroonSignatureAndVerificationContext =
                        verify(signatureSoFarForDischargeMacaroon, new LinkedList<>(possibleDischargeMacaroon.caveats), contextForVerificationDischargeMacaroon);
                String calculatedSignatureDischargeMacaroon = bindSignatureForRequest(resultingDischargeMacaroonSignatureAndVerificationContext.getLeft());
                if (possibleDischargeMacaroon.macaroonSignature.equals(calculatedSignatureDischargeMacaroon)) {
                    /*
                        So far, the third-party caveat is diffused, but the context may become invalid by checking another caveat.
                        If that will be ever the case later on, the exception will be caught in this try-catch block, and another
                        discharge macaroon will be used.
                     */
                    signatureSoFar = calculateMAC(signatureSoFar, calculateVldCldConcatenationThirdPartyCaveat(caveat));
                    return verify(signatureSoFar, remainingCaveatsToVerifyInContext, resultingDischargeMacaroonSignatureAndVerificationContext.getRight());
                }
            } catch (Exception ignored) {}
        }

        throw new IllegalStateException(("%d corresponding discharge macaroon(s) found for third-party caveat (%s), " +
                "but none could be used for the diffuse process.").formatted(correspondingDischargeMacaroons.size(), caveat));
    }

    private byte[] calculateVldCldConcatenationThirdPartyCaveat(@NotNull ThirdPartyCaveat caveat) {
        byte[] toMAC = new byte[caveat.getCaveatRootOrVerificationKey().length + caveat.getCaveatIdentifier().length];
        System.arraycopy(caveat.getCaveatRootOrVerificationKey(), 0, toMAC, 0, caveat.getCaveatRootOrVerificationKey().length);
        System.arraycopy(caveat.getCaveatIdentifier(), 0, toMAC, caveat.getCaveatRootOrVerificationKey().length, caveat.getCaveatIdentifier().length);
        return toMAC;
    }

    /**
     * Getter for the bound discharge Macaroons.
     * @return  The bound discharge Macaroons.
     */
    public @NotNull Map<byte[], @NotNull Set<@NotNull Macaroon>> getBoundMacaroons() {
        return boundMacaroons;
    }
}
