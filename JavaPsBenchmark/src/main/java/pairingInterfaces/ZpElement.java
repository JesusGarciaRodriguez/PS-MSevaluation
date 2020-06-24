package pairingInterfaces;



/**
 * Interface for the elements of the Zp used in the scheme.
 */
public interface ZpElement {

    /**
     * Addition over Zp.
     * @param el2 Element to add.
     * @return this+el2 mod p.
     */
    ZpElement add(ZpElement el2);

    /**
     * Multiplication over Zp.
     * @param el2 Element to multiply.
     * @return this*el2 mod p.
     */
    ZpElement mul(ZpElement el2);

    /**
     * Subtraction over Zp.
     * @param el2 Element to subtract.
     * @return this-el2 mod p.
     */
    ZpElement sub(ZpElement el2);

    /**
     * Negate this element over Zp.
     * @return -this mod p.
     */
    ZpElement neg();

    /**
     * Return the (multiplicative) inverse of this element over Zp
     * @return 1/this mod p
     */
    ZpElement inverse();

    /**
     * @return True if the element is one or false if not
     */
    boolean isUnity();

}
