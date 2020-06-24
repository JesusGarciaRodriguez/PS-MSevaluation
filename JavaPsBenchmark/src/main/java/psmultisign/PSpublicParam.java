package psmultisign;

import multisign.MSauxArg;
import multisign.MSpublicParam;

/**
 * Implementation of the public parameters for PS signatures.
 */
public class PSpublicParam implements MSpublicParam {
    private int n;
    private PSauxArg auxArg;

    public PSpublicParam(int n, PSauxArg auxArg) {
        this.n = n;
        this.auxArg = auxArg;
    }

    @Override
    public int getN() {
        return n;
    }

    @Override
    public MSauxArg getAuxArg() {
        return auxArg;
    }
}
