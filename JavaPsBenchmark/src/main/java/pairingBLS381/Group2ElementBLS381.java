package pairingBLS381;

import pairingInterfaces.Group2Element;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BLS381.ECP2;
import org.apache.milagro.amcl.BLS381.PAIR;

public class Group2ElementBLS381 implements Group2Element {

    ECP2 x;

    Group2ElementBLS381(ECP2 x){
        this.x=x;//Copy?
    }

    @Override
    public Group2ElementBLS381 mul(Group2Element el2) {
        if(!(el2 instanceof Group2ElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group2ElementBLS381 e2=(Group2ElementBLS381)el2;
        Group2ElementBLS381 res=new Group2ElementBLS381(new ECP2(x));
        res.x.add(e2.x);
        return res;
    }

    @Override
    public Group2ElementBLS381 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS381 e=(ZpElementBLS381)exp;
        return new Group2ElementBLS381(PAIR.G2mul(x,e.x));
    }

    @Override
    public Group2Element invExp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS381 e=(ZpElementBLS381)exp;
        return this.exp(e.neg());
    }

    @Override
    public boolean isUnity() {
        return x.is_infinity(); //I think this is correct as it is the neutral element in addition (that we represent as multiplication).
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Group2ElementBLS381 that = (Group2ElementBLS381) o;
        return x.equals(that.x);
    }

}
