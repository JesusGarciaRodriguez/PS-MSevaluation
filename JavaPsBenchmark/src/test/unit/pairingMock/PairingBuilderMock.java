package unit.pairingMock;

import pairingInterfaces.*;

public class PairingBuilderMock implements PairingBuilder {


    @Override
    public Pairing getPairing() {
        return null;
    }

    @Override
    public Group1Element getGroup1Generator() {
        return null;
    }

    @Override
    public Group2Element getGroup2Generator() {
        return null;
    }

    @Override
    public Group3Element getGroup3Generator() {
        return null;
    }

    @Override
    public ZpElement getRandomZpElement() {
        return null;
    }

    @Override
    public Hash0 getHash0() {
        return null;
    }

    @Override
    public Hash1 getHash1() {
        return null;
    }

    @Override
    public Hash2 getHash2() {
        return null;
    }
}
