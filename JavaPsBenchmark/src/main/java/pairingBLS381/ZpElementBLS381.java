package pairingBLS381;

import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BLS381.BIG;

public class ZpElementBLS381 implements ZpElement {

    BIG x;

    public ZpElementBLS381(BIG x){
        this.x=new BIG(x);
        while (BIG.comp(this.x, new BIG(0)) < 0) {
            this.x.add(PairingBLS381.p);
        }
        this.x.mod(PairingBLS381.p);
    }

    @Override
    public ZpElementBLS381 add(ZpElement el2) {
        if(!(el2 instanceof ZpElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS381 e=(ZpElementBLS381)el2;
        BIG res=x.plus(e.x);
        res.mod(PairingBLS381.p);
        return new ZpElementBLS381(res);
    }

    @Override
    public ZpElementBLS381 mul(ZpElement el2) {
        if(!(el2 instanceof ZpElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS381 e=(ZpElementBLS381)el2;
        BIG res=BIG.modmul(x,e.x, PairingBLS381.p);
        return new ZpElementBLS381(res);
    }

    @Override
    public ZpElementBLS381 sub(ZpElement el2) {
        if(!(el2 instanceof ZpElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS381 e=(ZpElementBLS381)el2;
        BIG res=new BIG(x);
        while (BIG.comp(res, e.x) < 0) { // Patch bug of efficiency
            res.add(PairingBLS381.p);
        }
        res.sub(e.x);
        res.mod(PairingBLS381.p);
        return new ZpElementBLS381(res);
    }

    @Override
    public ZpElementBLS381 neg() {
        return new ZpElementBLS381(BIG.modneg(x, PairingBLS381.p));
    }

    @Override
    public ZpElement inverse() {
        BIG x=new BIG(this.x);
        x.invmodp(PairingBLS381.p);
        return new ZpElementBLS381(x);
    }

    @Override
    public boolean isUnity() {
        return x.isunity();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZpElementBLS381 that = (ZpElementBLS381) o;
        return (BIG.comp(x,that.x)==0);
    }

}
