package pairingInterfaces;

/**
 * Interface for the elements of the second group of the pairing.
 */
public interface Group2Element {

    /**
     * Multiplicative operation of the group (both elements are not modified)
     * @param el2 Element to be multiplied.
     * @return this*el2.
     */
    public Group2Element mul(Group2Element el2);

    /**
     * Exponentiation operation of the group (both elements are not modified)
     * @param exp Exponent.
     * @return this^exp.
     */
    public Group2Element exp(ZpElement exp);

    /**
     * Inverse exponentiation (both elements are not modified)
     * @param exp Exponent.
     * @return this^(-exp).
     */
    Group2Element invExp(ZpElement exp);

    /**
     * Check if the element is a unit.
     * @return this==1G
     */
    boolean isUnity();


}
