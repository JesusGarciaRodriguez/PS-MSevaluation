package pairingBLS461;

import pairingInterfaces.*;
import org.apache.milagro.amcl.BLS461.BIG;
import org.apache.milagro.amcl.BLS461.ECP;
import org.apache.milagro.amcl.BLS461.ECP2;
import org.apache.milagro.amcl.RAND;
import java.security.SecureRandom;

public class PairingBuilderBLS461 implements PairingBuilder {

    private RAND rng;

    public PairingBuilderBLS461(){
        int seedLength = PairingBLS461.FIELD_BYTES;
        SecureRandom random = new SecureRandom();
        byte[] seed = random.generateSeed(seedLength);

        // create a new amcl.RAND and initialize it with the generated seed
        rng = new RAND();
        rng.clean();
        rng.seed(seedLength, seed);
    }

    @Override
    public Pairing getPairing() {
        return new PairingBLS461();
    }

    @Override
    public Group1ElementBLS461 getGroup1Generator() {
        return new Group1ElementBLS461(ECP.generator());
    }

    @Override
    public Group2ElementBLS461 getGroup2Generator() {
        return new Group2ElementBLS461(ECP2.generator());
    }

    @Override
    public Group3Element getGroup3Generator() {
        return getPairing().pair(getGroup1Generator(),getGroup2Generator());
    }

    @Override
    public ZpElementBLS461 getRandomZpElement() {
        return new ZpElementBLS461(BIG.randomnum(PairingBLS461.p, rng));
    }

    @Override
    public Hash0 getHash0() {
        return new Hash0BLS461();
    }

    @Override
    public Hash1 getHash1() {
        return new Hash1BLS461();
    }

    @Override
    public Hash2 getHash2() { return new Hash2BLS461(); }
}
