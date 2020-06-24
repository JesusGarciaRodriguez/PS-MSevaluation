package pairingInterfaces;

/**
 * Interface for the elements of the third group of the pairing.
 */
public interface Group3Element {

    /**
     * Multiplicative operation of the group (both elements are not modified)
     * @param el2 Element to be multiplied.
     * @return this*el2.
     */
    public Group3Element mul(Group3Element el2);

    /**
     * Exponentiation operation of the group (both elements are not modified)
     * @param exp Exponent.
     * @return this^exp.
     */
    public Group3Element exp(ZpElement exp);

    /**
     * Inverse exponentiation (both elements are not modified)
     * @param exp Exponent.
     * @return this^(-exp).
     */
    Group3Element invExp(ZpElement exp);

    /**
     * Check if the element is a unit.
     * @return this==1G
     */
    public boolean isUnity();
}
