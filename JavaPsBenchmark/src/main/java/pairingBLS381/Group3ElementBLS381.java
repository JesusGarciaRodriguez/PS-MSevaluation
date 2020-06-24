package pairingBLS381;

import pairingInterfaces.Group3Element;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BLS381.FP12;

public class Group3ElementBLS381 implements Group3Element {
    FP12 x;

    Group3ElementBLS381(FP12 x){
        this.x=x;//Copy?
    }

    public Group3ElementBLS381 mul(Group3Element el2) {
        if(!(el2 instanceof Group3ElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group3ElementBLS381 e2=(Group3ElementBLS381)el2;
        Group3ElementBLS381 res=new Group3ElementBLS381(new FP12(x));
        res.x.mul(e2.x);
        return res;
    }

    @Override
    public Group3ElementBLS381 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS381 e=(ZpElementBLS381)exp;
        // pow supposedly consumes too much RAM. However, every exponentiation
        // can be made over Group1 (or 2), because of pairing properties, as reflected on D4.1
        return new Group3ElementBLS381(x.pow(e.x));
    }

    @Override
    public Group3Element invExp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS381 e=(ZpElementBLS381)exp;
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
        Group3ElementBLS381 that = (Group3ElementBLS381) o;
        return x.equals(that.x);
    }
}
