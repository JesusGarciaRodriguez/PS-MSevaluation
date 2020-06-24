package psmultisign;

import multisign.MSsignature;
import pairingInterfaces.Group1Element;
import pairingInterfaces.ZpElement;

/**
 * Signature obtained using a PS signing scheme.
 */
public class PSsignature implements MSsignature {

    private ZpElement mPrim;
    private Group1Element sigma1;
    private Group1Element sigma2;

    public PSsignature(ZpElement mPrim, Group1Element sigma1, Group1Element sigma2) {
        this.mPrim = mPrim;
        this.sigma1 = sigma1;
        this.sigma2 = sigma2;
    }


    public ZpElement getMPrim() {
        return mPrim;
    }

    public Group1Element getSigma1() {
        return sigma1;
    }

    public Group1Element getSigma2() {
        return sigma2;
    }

}
