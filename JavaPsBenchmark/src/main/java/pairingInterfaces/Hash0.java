package pairingInterfaces;

import utils.Pair;

import java.util.Collection;

/**
 * Interface for the hash function H0:Z^k -> Zp x G needed for the PS scheme.
 */
public interface Hash0 {

    /**
     * Obtain the result of the hash function.
     * @param m An array of Zp elements.
     * @return A Zp element and a Group1 element.
     */
    Pair<ZpElement,Group1Element> hash(Collection<ZpElement> m);
}
