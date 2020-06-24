package pairingBLS461;

import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BLS461.BIG;

public class ZpElementBLS461 implements ZpElement {

    BIG x;

    public ZpElementBLS461(BIG x){
        this.x=new BIG(x);
        while (BIG.comp(this.x, new BIG(0)) < 0) {
            this.x.add(PairingBLS461.p);
        }
        this.x.mod(PairingBLS461.p);
    }

    @Override
    public ZpElementBLS461 add(ZpElement el2) {
        if(!(el2 instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)el2;
        BIG res=x.plus(e.x);
        res.mod(PairingBLS461.p);
        return new ZpElementBLS461(res);
    }

    @Override
    public ZpElementBLS461 mul(ZpElement el2) {
        if(!(el2 instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)el2;
        BIG res=BIG.modmul(x,e.x, PairingBLS461.p);
        return new ZpElementBLS461(res);
    }

    @Override
    public ZpElementBLS461 sub(ZpElement el2) {
        if(!(el2 instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)el2;
        BIG res=new BIG(x);
        while (BIG.comp(res, e.x) < 0) { // Patch bug of efficiency
            res.add(PairingBLS461.p);
        }
        res.sub(e.x);
        res.mod(PairingBLS461.p);
        return new ZpElementBLS461(res);
    }

    @Override
    public ZpElementBLS461 neg() {
        return new ZpElementBLS461(BIG.modneg(x, PairingBLS461.p));
    }

    @Override
    public ZpElement inverse() {
        BIG x=new BIG(this.x);
        x.invmodp(PairingBLS461.p);
        return new ZpElementBLS461(x);
    }

    @Override
    public boolean isUnity() {
        return x.isunity();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZpElementBLS461 that = (ZpElementBLS461) o;
        return (BIG.comp(x,that.x)==0);
    }

}
