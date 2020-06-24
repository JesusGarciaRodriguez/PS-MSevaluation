package pairingBN254;

import pairingInterfaces.*;
import org.apache.milagro.amcl.BN254.BIG;
import org.apache.milagro.amcl.BN254.ECP;
import org.apache.milagro.amcl.BN254.ECP2;
import org.apache.milagro.amcl.RAND;
import java.security.SecureRandom;

public class PairingBuilderBN254 implements PairingBuilder {

    private RAND rng;

    public PairingBuilderBN254(){
        int seedLength = PairingBN254.FIELD_BYTES;
        SecureRandom random = new SecureRandom();
        byte[] seed = random.generateSeed(seedLength);

        // create a new amcl.RAND and initialize it with the generated seed
        rng = new RAND();
        rng.clean();
        rng.seed(seedLength, seed);
    }

    @Override
    public Pairing getPairing() {
        return new PairingBN254();
    }

    @Override
    public Group1ElementBN254 getGroup1Generator() {
        return new Group1ElementBN254(ECP.generator());
    }

    @Override
    public Group2ElementBN254 getGroup2Generator() {
        return new Group2ElementBN254(ECP2.generator());
    }

    @Override
    public Group3Element getGroup3Generator() {
        return getPairing().pair(getGroup1Generator(),getGroup2Generator());
    }

    @Override
    public ZpElementBN254 getRandomZpElement() {
        return new ZpElementBN254(BIG.randomnum(PairingBN254.p, rng));
    }

    @Override
    public Hash0 getHash0() {
        return new Hash0BN254();
    }

    @Override
    public Hash1 getHash1() {
        return new Hash1BN254();
    }

    @Override
    public Hash2 getHash2() { return new Hash2BN254(); }
}
