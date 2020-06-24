package unit.pairingMock;


import pairingInterfaces.Group1Element;
import pairingInterfaces.ZpElement;

public class Group1ElementMock implements Group1Element {

    @Override
    public Group1Element mul(Group1Element el2) {
        return null;
    }

    @Override
    public Group1Element exp(ZpElement exp) {
        return null;
    }

    @Override
    public Group1Element invExp(ZpElement exp) {
        return null;
    }

    @Override
    public boolean isUnity() {
        return false;
    }
}
