package unit.pairingMock;

import pairingInterfaces.Group2Element;
import pairingInterfaces.ZpElement;

public class Group2ElementMock implements Group2Element {


    @Override
    public Group2Element mul(Group2Element el2) {
        return null;
    }

    @Override
    public Group2Element exp(ZpElement exp) {
        return null;
    }

    @Override
    public Group2Element invExp(ZpElement exp) {
        return null;
    }

    @Override
    public boolean isUnity() {
        return false;
    }

}
