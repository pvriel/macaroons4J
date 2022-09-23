package vrielynckpieterjan.macaroons4j;

import org.jetbrains.annotations.NotNull;

import java.util.*;

public abstract class Macaroon {

    private final @NotNull String hintTargetLocation;
    private final byte[] macaroonIdentifier;
    private final @NotNull List<@NotNull Caveat> caveats = new LinkedList<>();
    // Is set to protected for testing purposes: don't actually change this!
    protected @NotNull String macaroonSignature;
    private final @NotNull Map<byte[], @NotNull Set<@NotNull Macaroon>> boundMacaroons = new HashMap<>();

    protected abstract @NotNull String calculateMAC(@NotNull String key, byte[] element);
    protected abstract byte[] encrypt(@NotNull String key, byte[] original) throws Exception;
    protected abstract @NotNull String decrypt(@NotNull String key, byte[] encrypted) throws Exception;
    protected abstract @NotNull String bindSignatureForRequest(@NotNull String originalSignature);

    public Macaroon(@NotNull String secretString, byte[] macaroonIdentifier, @NotNull String hintTargetLocation) {
        this.hintTargetLocation = hintTargetLocation;
        this.macaroonIdentifier = macaroonIdentifier;
        this.macaroonSignature = calculateMAC(secretString, macaroonIdentifier);
    }

    private void addCaveat(@NotNull Caveat caveat, byte[] toMac) {
        this.caveats.add(caveat);
        this.macaroonSignature = calculateMAC(this.macaroonSignature, toMac);
    }

    public void addCaveat(@NotNull FirstPartyCaveat caveat) {
        addCaveat(caveat, caveat.getCaveatIdentifier());
    }

    public void addCaveat(@NotNull ThirdPartyCaveat caveat) throws Exception {
        caveat.setCaveatRootOrVerificationKey(encrypt(this.macaroonSignature, caveat.getCaveatRootOrVerificationKey()));
        byte[] toMAC = calculateVldCldConcatenationThirdPartyCaveat(caveat);
        addCaveat(caveat, toMAC);
    }

    public void bindMacaroonForRequest(@NotNull Macaroon dischargeMacaroon) {
        dischargeMacaroon.macaroonSignature = bindSignatureForRequest(dischargeMacaroon.macaroonSignature);

        if (!boundMacaroons.containsKey(dischargeMacaroon.macaroonIdentifier)) { // TODO: double-check that this does not give any problems: comparison between byte arrays.
            boundMacaroons.put(dischargeMacaroon.macaroonIdentifier, new HashSet<>());
        }
        Set<Macaroon> boundMacaroonsForIdentifierDischargeMacaroon = boundMacaroons.get(dischargeMacaroon.macaroonIdentifier);
        boundMacaroonsForIdentifierDischargeMacaroon.add(dischargeMacaroon);
    }

    public void verify(@NotNull String secretString, @NotNull VerificationContext context) throws Exception {
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
        signatureSoFar = verify(signatureSoFar, remainingCaveatsToVerifyInContext, context);
        if (!signatureSoFar.equals(macaroonSignature)) {
            throw new IllegalStateException("The signature of the macaroon is not valid: the signature of the macaroon is %s, but the signature that was reconstructed is %s.".formatted(macaroonSignature, signatureSoFar));
        }
    }

    private @NotNull String verify(@NotNull String signatureSoFar, @NotNull List<Caveat> remainingCaveatsToVerifyInContext, @NotNull VerificationContext context) throws Exception {
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

        return signatureSoFar;
    }

    private @NotNull String verify(@NotNull String signatureSoFar, @NotNull FirstPartyCaveat caveat, @NotNull VerificationContext context) throws IllegalStateException {
        caveat.verify(this, context);
        return calculateMAC(signatureSoFar, caveat.getCaveatIdentifier());
    }

    private @NotNull String verify(@NotNull String signatureSoFar, @NotNull ThirdPartyCaveat caveat,
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
                String calculatedSignatureDischargeMacaroon = bindSignatureForRequest(verify(signatureSoFarForDischargeMacaroon,
                        new LinkedList<>(possibleDischargeMacaroon.caveats), contextForVerificationDischargeMacaroon));
                if (possibleDischargeMacaroon.macaroonSignature.equals(calculatedSignatureDischargeMacaroon)) {
                    /*
                        So far, the third-party caveat is diffused, but the context may become invalid by checking another caveat.
                        If that will be ever the case later on, the exception will be caught in this try-catch block, and another
                        discharge macaroon will be used.
                     */
                    signatureSoFar = calculateMAC(signatureSoFar, calculateVldCldConcatenationThirdPartyCaveat(caveat));
                    return verify(signatureSoFar, remainingCaveatsToVerifyInContext, context);
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
}
