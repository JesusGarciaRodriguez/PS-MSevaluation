package unit.multisingMock;


import multisign.MSauxArg;
import multisign.MSpublicParam;

/**
 * Implementation of the public parameters for PS signatures.
 */
public class MockPublicParam implements MSpublicParam {

    @Override
    public int getN() {
        return 0;
    }

    @Override
    public MSauxArg getAuxArg() {
        return null;
    }
}
