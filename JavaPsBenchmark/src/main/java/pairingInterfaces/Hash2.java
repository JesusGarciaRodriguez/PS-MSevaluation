package pairingInterfaces;

import psmultisign.PSverfKey;

/**
 * Interface for the hash function H2: VerfKey x  G1 x G1 x G3-> Zp needed for the PS scheme (ZK presentation token).
 */
public interface Hash2 {

    /**
     * Obtain the result of the hash function.
     * @param m Message.
     * @param avk PS verification key.
     * @param sigma1 Group1 element.
     * @param sigma2 Group1 element.
     * @param prodT Group3 element.
     * @return A Zp element.
     */
    ZpElement hash(String m, PSverfKey avk, Group1Element sigma1, Group1Element sigma2, Group3Element prodT);
}
