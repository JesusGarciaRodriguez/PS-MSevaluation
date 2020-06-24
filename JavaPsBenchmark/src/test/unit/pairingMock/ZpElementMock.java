package unit.pairingMock;


import pairingInterfaces.ZpElement;

public class ZpElementMock implements ZpElement {

    @Override
    public ZpElement add(ZpElement el2) {
        return null;
    }

    @Override
    public ZpElement mul(ZpElement el2) {
        return null;
    }

    @Override
    public ZpElement sub(ZpElement el2) {
        return null;
    }

    @Override
    public ZpElement neg() {
        return null;
    }

    @Override
    public ZpElement inverse() {
        return null;
    }

    @Override
    public boolean isUnity() {
        return false;
    }

}
