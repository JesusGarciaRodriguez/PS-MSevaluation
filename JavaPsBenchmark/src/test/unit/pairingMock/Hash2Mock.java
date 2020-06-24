package unit.pairingMock;


import pairingInterfaces.Group1Element;
import pairingInterfaces.Group3Element;
import pairingInterfaces.Hash2;
import pairingInterfaces.ZpElement;
import psmultisign.PSverfKey;

public class Hash2Mock implements Hash2 {


    @Override
    public ZpElement hash(String m, PSverfKey avk, Group1Element sigma1, Group1Element sigma2, Group3Element prodT) {
        return null;
    }
}
