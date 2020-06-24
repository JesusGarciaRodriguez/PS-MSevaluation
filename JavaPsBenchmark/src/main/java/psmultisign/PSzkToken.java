package psmultisign;

import multisign.MSzkToken;
import pairingInterfaces.Group1Element;
import pairingInterfaces.ZpElement;

import java.util.Map;

/**
 * Presentation token for ZK proofs in a PS-MS signature scheme.
 */
public class PSzkToken implements MSzkToken {

    private Group1Element sigma1;
    private Group1Element sigma2;
    private ZpElement c;
    private Map<String, ZpElement> v_aj;
    private ZpElement v_t;
    private ZpElement v_aPrim;

    public PSzkToken(Group1Element sigma1, Group1Element sigma2, ZpElement c, Map<String, ZpElement> vaj, ZpElement vt, ZpElement vaPrim) {
        this.sigma1 = sigma1;
        this.sigma2 = sigma2;
        this.c = c;
        this.v_aj = vaj;
        this.v_t = vt;
        this.v_aPrim = vaPrim;
    }



    public Group1Element getSigma1() {
        return sigma1;
    }

    public Group1Element getSigma2() {
        return sigma2;
    }

    public ZpElement getC() {
        return c;
    }

    public Map<String, ZpElement> getV_aj() {
        return v_aj;
    }

    public ZpElement getV_t() {
        return v_t;
    }

    public ZpElement getV_aPrim() {
        return v_aPrim;
    }

}
