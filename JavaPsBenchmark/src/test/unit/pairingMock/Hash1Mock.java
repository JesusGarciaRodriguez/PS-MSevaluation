package unit.pairingMock;


import pairingInterfaces.Hash1;
import pairingInterfaces.ZpElement;
import psmultisign.PSverfKey;

public class Hash1Mock implements Hash1 {

    @Override
    public ZpElement[] hash(PSverfKey[] vks) {
        return new ZpElement[0];
    }
}
