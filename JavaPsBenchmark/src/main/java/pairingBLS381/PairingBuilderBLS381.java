package pairingBLS381;

import pairingInterfaces.*;
import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP;
import org.apache.milagro.amcl.BLS381.ECP2;
import org.apache.milagro.amcl.RAND;
import java.security.SecureRandom;

public class PairingBuilderBLS381 implements PairingBuilder {

    private RAND rng;

    public PairingBuilderBLS381(){
        int seedLength = PairingBLS381.FIELD_BYTES;
        SecureRandom random = new SecureRandom();
        byte[] seed = random.generateSeed(seedLength);

        // create a new amcl.RAND and initialize it with the generated seed
        rng = new RAND();
        rng.clean();
        rng.seed(seedLength, seed);
    }

    @Override
    public Pairing getPairing() {
        return new PairingBLS381();
    }

    @Override
    public Group1ElementBLS381 getGroup1Generator() {
        return new Group1ElementBLS381(ECP.generator());
    }

    @Override
    public Group2ElementBLS381 getGroup2Generator() {
        return new Group2ElementBLS381(ECP2.generator());
    }

    @Override
    public Group3Element getGroup3Generator() {
        return getPairing().pair(getGroup1Generator(),getGroup2Generator());
    }

    @Override
    public ZpElementBLS381 getRandomZpElement() {
        return new ZpElementBLS381(BIG.randomnum(PairingBLS381.p, rng));
    }


    @Override
    public Hash0 getHash0() {
        return new Hash0BLS381();
    }

    @Override
    public Hash1 getHash1() {
        return new Hash1BLS381();
    }

    @Override
    public Hash2 getHash2() { return new Hash2BLS381(); }
}
