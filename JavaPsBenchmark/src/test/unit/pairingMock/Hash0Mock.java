package unit.pairingMock;


import pairingInterfaces.Group1Element;
import pairingInterfaces.Hash0;
import pairingInterfaces.ZpElement;
import utils.Pair;
import java.util.Collection;

public class Hash0Mock implements Hash0 {

    @Override
    public Pair<ZpElement, Group1Element> hash(Collection<ZpElement> m) {
        return null;
    }
}
