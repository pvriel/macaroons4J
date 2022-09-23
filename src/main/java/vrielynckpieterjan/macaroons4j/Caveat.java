package vrielynckpieterjan.macaroons4j;

abstract class Caveat {

    private final byte[] caveatIdentifier;

    protected Caveat(byte[] caveatIdentifier) {
        this.caveatIdentifier = caveatIdentifier;
    }

    byte[] getCaveatIdentifier() {
        return caveatIdentifier;
    }
}
