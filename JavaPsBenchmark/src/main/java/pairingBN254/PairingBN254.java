package pairingBN254;

import pairingInterfaces.Group1Element;
import pairingInterfaces.Group2Element;
import pairingInterfaces.Group3Element;
import pairingInterfaces.Pairing;
import utils.Pair;
import org.apache.milagro.amcl.BN254.*;

import java.util.Collection;

public class PairingBN254 implements Pairing {

    static final BIG p=new BIG(ROM.CURVE_Order);
    static final int FIELD_BYTES=CONFIG_BIG.MODBYTES;


    @Override
    public Group3ElementBN254 pair(Group1Element el1, Group2Element el2) {
        if(!(el1 instanceof Group1ElementBN254))
            throw new IllegalArgumentException("el1 must be Group1ElementBN254");
        if(!(el2 instanceof Group2ElementBN254))
            throw new IllegalArgumentException("el2 must be Group2ElementBN254");
        ECP e1= ((Group1ElementBN254) el1).x;
        ECP2 e2= ((Group2ElementBN254) el2).x;
        return new Group3ElementBN254(PAIR.fexp(PAIR.ate(e2,e1)));
    }

    @Override
    public Group3Element multiPair(Collection<Pair<Group1Element,Group2Element>> elements) {
        FP12[] r=PAIR.initmp();
        for(Pair<Group1Element,Group2Element> el:elements){
            if(!(el.getFirst() instanceof Group1ElementBN254))
                throw new IllegalArgumentException("el1 must be Group1ElementBN254");
            if(!(el.getSecond()   instanceof Group2ElementBN254))
                throw new IllegalArgumentException("el2 must be Group2ElementBN254");
            ECP e1= ((Group1ElementBN254) el.getFirst()).x;
            ECP2 e2= ((Group2ElementBN254) el.getSecond()).x;
            PAIR.another(r,e2,e1);
        }
        FP12 f=PAIR.miller(r);
        return new Group3ElementBN254(PAIR.fexp(f));
    }

}
