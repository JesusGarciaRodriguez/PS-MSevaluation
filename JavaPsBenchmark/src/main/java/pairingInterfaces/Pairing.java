package pairingInterfaces;

import utils.Pair;

import java.util.Collection;

/**
 * Pairing to be used in the signature scheme.
 */
public interface Pairing {

    /**
     * Calculate the mapping of elements el1, el2.
     * @param el1 Element from group 1.
     * @param el2 Element from group 2.
     * @return e(el1,el2)
     */
    Group3Element pair(Group1Element el1, Group2Element el2);

    /**
     * Calculate the n-pairing.
     * @param elements Pairs of elements that compose the multi-pairing.
     * @return e(elements[0].first,elements[0].second)···e(elements[n-1].first,elements[n-1].second)
     */
    Group3Element multiPair(Collection<Pair<Group1Element,Group2Element>> elements);


}
