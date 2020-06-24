package unit.pairingMock;


import pairingInterfaces.Group1Element;
import pairingInterfaces.Group2Element;
import pairingInterfaces.Group3Element;
import pairingInterfaces.Pairing;
import utils.Pair;

import java.util.Collection;

public class PairingMock implements Pairing {

    @Override
    public Group3Element pair(Group1Element el1, Group2Element el2) {
        return null;
    }

    @Override
    public Group3Element multiPair(Collection<Pair<Group1Element, Group2Element>> elements) {
        return null;
    }
}
