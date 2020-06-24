package pairingBN254;

import pairingInterfaces.Group3Element;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BN254.FP12;

public class Group3ElementBN254 implements Group3Element {
    FP12 x;

    Group3ElementBN254(FP12 x){
        this.x=x;//Copy?
    }

    public Group3ElementBN254 mul(Group3Element el2) {
        if(!(el2 instanceof Group3ElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group3ElementBN254 e2=(Group3ElementBN254)el2;
        Group3ElementBN254 res=new Group3ElementBN254(new FP12(x));
        res.x.mul(e2.x);
        return res;
    }

    @Override
    public Group3ElementBN254 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBN254 e=(ZpElementBN254)exp;
        // pow supposedly consumes too much RAM. However, every exponentiation
        // can be made over Group1 (or 2), because of pairing properties, as reflected on D4.1
        return new Group3ElementBN254(x.pow(e.x));
    }

    @Override
    public Group3Element invExp(ZpElement exp) {
        if(!(exp instanceof ZpElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBN254 e=(ZpElementBN254)exp;
        return this.exp(e.neg());
    }

    @Override
    public boolean isUnity() {
        return x.isunity();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Group3ElementBN254 that = (Group3ElementBN254) o;
        return x.equals(that.x);
    }
}
