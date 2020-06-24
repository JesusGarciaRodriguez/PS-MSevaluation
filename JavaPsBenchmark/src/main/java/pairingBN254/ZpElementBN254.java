package pairingBN254;

import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BN254.BIG;

public class ZpElementBN254 implements ZpElement {

    BIG x;

    public ZpElementBN254(BIG x){
        this.x=new BIG(x);
        while (BIG.comp(this.x, new BIG(0)) < 0) {
            this.x.add(PairingBN254.p);
        }
        this.x.mod(PairingBN254.p);
    }

    @Override
    public ZpElementBN254 add(ZpElement el2) {
        if(!(el2 instanceof ZpElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBN254 e=(ZpElementBN254)el2;
        BIG res=x.plus(e.x);
        res.mod(PairingBN254.p);
        return new ZpElementBN254(res);
    }

    @Override
    public ZpElementBN254 mul(ZpElement el2) {
        if(!(el2 instanceof ZpElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBN254 e=(ZpElementBN254)el2;
        BIG res=BIG.modmul(x,e.x, PairingBN254.p);
        return new ZpElementBN254(res);
    }

    @Override
    public ZpElementBN254 sub(ZpElement el2) {
        if(!(el2 instanceof ZpElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBN254 e=(ZpElementBN254)el2;
        BIG res=new BIG(x);
        while (BIG.comp(res, e.x) < 0) { // Patch bug of efficiency
            res.add(PairingBN254.p);
        }
        res.sub(e.x);
        res.mod(PairingBN254.p);
        return new ZpElementBN254(res);
    }

    @Override
    public ZpElementBN254 neg() {
        return new ZpElementBN254(BIG.modneg(x, PairingBN254.p));
    }

    @Override
    public ZpElement inverse() {
        BIG x=new BIG(this.x);
        x.invmodp(PairingBN254.p);
        return new ZpElementBN254(x);
    }

    @Override
    public boolean isUnity() {
        return x.isunity();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZpElementBN254 that = (ZpElementBN254) o;
        return (BIG.comp(x,that.x)==0);
    }

}
