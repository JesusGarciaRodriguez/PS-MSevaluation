package psmultisign;

import multisign.MSverfKey;
import pairingInterfaces.Group2Element;

import java.util.Map;
import java.util.Objects;

/**
 * Verification key for a PS signing scheme.
 */
public class PSverfKey implements MSverfKey {

    private Group2Element vx;
    private Group2Element vy_m;
    private Group2Element vy_epoch;
    private Map<String, Group2Element> vy;

    public PSverfKey(Group2Element vx, Group2Element vy_m, Map<String, Group2Element> vy, Group2Element vy_epoch) {
        this.vx = vx;
        this.vy_m = vy_m;
        this.vy = vy;
        this.vy_epoch=vy_epoch;
    }

    public Group2Element getVX() {
        return vx;
    }

    public Group2Element getVY_m() {
        return vy_m;
    }

    public Group2Element getVY_epoch() {
        return vy_epoch;
    }

    public Map<String, Group2Element> getVY() {
        return vy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PSverfKey pSverfKey = (PSverfKey) o;
        return Objects.equals(vx, pSverfKey.vx) &&
                Objects.equals(vy_m, pSverfKey.vy_m) &&
                Objects.equals(vy, pSverfKey.vy);
    }
}
