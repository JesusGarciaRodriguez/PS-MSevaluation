package pairingInterfaces;


/**
 * Interface for the elements of the first group of the pairing.
 */
public interface Group1Element {

    /**
     * Multiplicative operation of the group (both elements are not modified)
     * @param el2 Element to be multiplied.
     * @return this*el2.
     */
    Group1Element mul(Group1Element el2);

    /**
     * Exponentiation operation of the group (both elements are not modified)
     * @param exp Exponent.
     * @return this^exp.
     */
    Group1Element exp(ZpElement exp);

    /**
     * Inverse exponentiation (both elements are not modified)
     * @param exp Exponent.
     * @return this^(-exp).
     */
    Group1Element invExp(ZpElement exp);

    /**
     * Check if the element is a unit.
     * @return this==1G
     */
    boolean isUnity();

}
