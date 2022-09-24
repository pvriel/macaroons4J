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
     * <br>This also means that a caveat can NOT be added multiple times to the Macaroon.
     * Instead, each time, a new Macaroon instance should be generated.
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
     * @throws  IllegalArgumentException
     *          If the discharge Macaroons has bound discharge Macaroons; these should be bound to this Macaroon instance instead.
     */
    public void bindMacaroonForRequest(@NotNull Macaroon dischargeMacaroon) {
        if (!dischargeMacaroon.boundMacaroons.isEmpty()) {
            throw new IllegalArgumentException("Discharge Macaroon has bound discharge Macaroons; these should be bound to this Macaroon instance instead.");
        }

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
     *          The verification context is cloned before the verification process takes place.
     * @throws  Exception
     *          If the verification process failed due to:
     *          <br>A) tampering with the signatures and/or caveats,
     *          <br>B) providing the wrong secret value of the Macaroon, or
     *          <br>C) the constraints of the caveats resulting in an impossible context.
     * @return  An equally or more strict verification context compared to the given {@link VerificationContext} instance,
     *          in which the constraints from the caveats of this Macaroon instance also hold.
     *          <br>The caveats are discharged and verified in a depth-first manner / in order.
     *          If there are multiple resulting verification contexts possible, only the first one will be returned.
     */
    public @NotNull VerificationContext verify(@NotNull String secretString, @NotNull VerificationContext context) throws Exception {
        String signature = calculateMAC(secretString, macaroonIdentifier);
        Pair<String, VerificationContext> signatureAndVerificationContext = verify(signature, new ArrayList<>(caveats), context.clone());
        signature = signatureAndVerificationContext.getLeft();
        VerificationContext verificationContext = signatureAndVerificationContext.getRight();

        if (!macaroonSignature.equals(signature)) throw new IllegalStateException("Macaroon signature is invalid.");
        System.gc(); // Lot of resources involved to optimally verify the Macaroon.
        return verificationContext;
    }

    private @NotNull Pair<@NotNull String, @NotNull VerificationContext> verify(@NotNull String signature,
            @NotNull List<@NotNull Caveat> remainingCaveats, @NotNull VerificationContext context) throws Exception {
        while (!remainingCaveats.isEmpty()) {
            Caveat currentCaveat = remainingCaveats.remove(0);
            if (currentCaveat instanceof FirstPartyCaveat) signature = verify(signature, (FirstPartyCaveat) currentCaveat, context);
            else if (currentCaveat instanceof ThirdPartyCaveat) {
                return verify(signature, remainingCaveats, (ThirdPartyCaveat) currentCaveat, context);
            } else {
                throw new IllegalStateException("Found a caveat (%s) that is neither a first-party nor a third-party caveat.".formatted(currentCaveat));
            }
        }
        return Pair.of(signature, context);
    }

    private @NotNull String verify(@NotNull String signature, @NotNull FirstPartyCaveat caveat, @NotNull VerificationContext context) throws Exception {
        caveat.verify(this, context);
        return calculateMAC(signature, caveat.getCaveatIdentifier());
    }

    private @NotNull Pair<@NotNull String, @NotNull VerificationContext> verify
            (@NotNull String signature, @NotNull List<@NotNull Caveat> remainingCaveats,
             @NotNull ThirdPartyCaveat caveat, @NotNull VerificationContext context) throws Exception {
        /*
            1. Generate the new signature for the Macaroon (we need this anyway).
                Also, generate the initial signature of the caveat (probably need this).
         */
        byte[] vldCldConcatenation = calculateVldCldConcatenationThirdPartyCaveat(caveat);
        String caveatRootKey = decrypt(signature, caveat.getCaveatRootOrVerificationKey());
        String initialSignatureDischargeMacaroon = calculateMAC(caveatRootKey, caveat.getCaveatIdentifier());
        signature = calculateMAC(signature, vldCldConcatenation);
        /*
            2. Check if we already verified a discharge Macaroon in this context that can be used to discharge this Macaroon instance.
                If that's the case, no additional work is required to verify this caveat; go to the next one.
         */
        if (context.caveatIdentifierIsAlreadyVerified(caveat.getCaveatIdentifier())) return verify(signature, remainingCaveats, context);
        //  3. Try to find a discharge Macaroon for the current caveat; take into account the impossible discharge Macaroons for better performance.
        Set<Macaroon> possibleDischargeMacaroons = boundMacaroons.getOrDefault(caveat.getCaveatIdentifier(), Set.of());
        possibleDischargeMacaroons = context.filterPossibleDischargeMacaroons(possibleDischargeMacaroons); // Filter the already invalid ones.

        for (Macaroon possibleDischargeMacaroon : possibleDischargeMacaroons) {
            try {
                /*
                Make a copy of the verification context. If the current discharge Macaroon can not be used for discharging
                the current caveat, this allows us to revert the additional restrictions it may have introduced within the
                verification context, to try to discharge the current caveat with another discharge Macaroon.

                However, if there's only one possible discharge Macaroon, just use the current verification context.
                In that case, we will never need to revert anyway.
                 */
                VerificationContext contextForDischargeMacaroon = (possibleDischargeMacaroons.size() == 1)? context : context.clone();
                /*
                Support for reflexive discharge Macaroons: already assume the discharge Macaroon holds.
                We check its caveats anyway.
                 */
                contextForDischargeMacaroon.addAlreadyVerifiedCaveatIdentifier(caveat.getCaveatIdentifier());
                Pair<String, VerificationContext> resultsVerificationDischargeMacaroon =
                        verify(initialSignatureDischargeMacaroon, new ArrayList<>(possibleDischargeMacaroon.caveats), contextForDischargeMacaroon);
                String currentSignatureDischargeMacaroon = resultsVerificationDischargeMacaroon.getLeft();
                currentSignatureDischargeMacaroon = bindSignatureForRequest(currentSignatureDischargeMacaroon);
                if (!possibleDischargeMacaroon.macaroonSignature.equals(currentSignatureDischargeMacaroon))
                    throw new IllegalStateException("Signature of discharge Macaroon (%s) is invalid.".formatted(possibleDischargeMacaroon));

                contextForDischargeMacaroon = resultsVerificationDischargeMacaroon.getRight();
                return verify(signature, remainingCaveats, contextForDischargeMacaroon);
            } catch (Exception ignored) {
                /*
                With the current restrictions holding in the verification context, the current discharge Macaroon can not be used for verification.
                That also means that we can not use the current discharge Macaroon in the future, in contexts that are (potentially) even more restricted.
                 */
                context.addInvalidDischargeMacaroon(possibleDischargeMacaroon);
            }
        }

        throw new IllegalStateException("No valid discharge Macaroon found for caveat (%s).".formatted(caveat));
    }

    private byte[] calculateVldCldConcatenationThirdPartyCaveat(@NotNull ThirdPartyCaveat caveat) {
        // No cache mechanism here; I don't think it would improve the performance of this method?
        byte[] toMAC = new byte[caveat.getCaveatRootOrVerificationKey().length + caveat.getCaveatIdentifier().length];
        System.arraycopy(caveat.getCaveatRootOrVerificationKey(), 0, toMAC, 0, caveat.getCaveatRootOrVerificationKey().length);
        System.arraycopy(caveat.getCaveatIdentifier(), 0, toMAC, caveat.getCaveatRootOrVerificationKey().length, caveat.getCaveatIdentifier().length);
        return toMAC;
    }
}
