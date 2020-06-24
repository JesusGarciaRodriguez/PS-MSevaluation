package pairingBLS381;

import pairingInterfaces.Group1Element;
import pairingInterfaces.Group2Element;
import pairingInterfaces.Group3Element;
import pairingInterfaces.Pairing;
import utils.Pair;
import org.apache.milagro.amcl.BLS381.*;

import java.util.Collection;

public class PairingBLS381 implements Pairing {

    static final BIG p=new BIG(ROM.CURVE_Order);
    static final int FIELD_BYTES=CONFIG_BIG.MODBYTES;


    @Override
    public Group3ElementBLS381 pair(Group1Element el1, Group2Element el2) {
        if(!(el1 instanceof Group1ElementBLS381))
            throw new IllegalArgumentException("el1 must be Group1ElementBLS381");
        if(!(el2 instanceof Group2ElementBLS381))
            throw new IllegalArgumentException("el2 must be Group2ElementBLS381");
        ECP e1= ((Group1ElementBLS381) el1).x;
        ECP2 e2= ((Group2ElementBLS381) el2).x;
        return new Group3ElementBLS381(PAIR.fexp(PAIR.ate(e2,e1)));
    }

    @Override
    public Group3Element multiPair(Collection<Pair<Group1Element,Group2Element>> elements) {
        FP12[] r=PAIR.initmp();
        for(Pair<Group1Element,Group2Element> el:elements){
            if(!(el.getFirst() instanceof Group1ElementBLS381))
                throw new IllegalArgumentException("el1 must be Group1ElementBLS381");
            if(!(el.getSecond()   instanceof Group2ElementBLS381))
                throw new IllegalArgumentException("el2 must be Group2ElementBLS381");
            ECP e1= ((Group1ElementBLS381) el.getFirst()).x;
            ECP2 e2= ((Group2ElementBLS381) el.getSecond()).x;
            PAIR.another(r,e2,e1);
        }
        FP12 f=PAIR.miller(r);
        return new Group3ElementBLS381(PAIR.fexp(f));
    }

}
