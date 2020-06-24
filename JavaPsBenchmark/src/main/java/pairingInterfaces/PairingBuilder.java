package pairingInterfaces;


public interface PairingBuilder {

    /**
     * @return Pairing object that contains pairing methods.
     */
    Pairing getPairing();

    /**
     * @return Generator of the first group of the pairing.
     */
    Group1Element getGroup1Generator();

    /**
     * @return Generator of the second group of the pairing.
     */
    Group2Element getGroup2Generator();

    /**
     * @return Generator of the third group of the pairing.
     */
    Group3Element getGroup3Generator();

    /**
     * @return Random element from Zp.
     */
    ZpElement getRandomZpElement();


    /**
     * @return Hash0 implementation.
     */
    Hash0 getHash0();

    /**
     * @return Hash1 implementation.
     */
    Hash1 getHash1();

    /**
     * @return Hash2 implementation.
     */
    Hash2 getHash2();

}
