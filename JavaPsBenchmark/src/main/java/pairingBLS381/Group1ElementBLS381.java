package pairingBLS381;

import pairingInterfaces.Group1Element;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BLS381.ECP;
import org.apache.milagro.amcl.BLS381.PAIR;

public class Group1ElementBLS381 implements Group1Element {

    ECP x;

    Group1ElementBLS381(ECP x){
        this.x=x; //Copy?
    }

    @Override
    public Group1ElementBLS381 mul(Group1Element el2) {
        if(!(el2 instanceof Group1ElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group1ElementBLS381 e2=(Group1ElementBLS381)el2;
        Group1ElementBLS381 res=new Group1ElementBLS381(new ECP(x));
        res.x.add(e2.x);
        return res;
    }

    @Override
    public Group1ElementBLS381 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS381))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS381 e=(ZpElementBLS381)exp;
        return new Group1ElementBLS381(PAIR.G1mul(x,e.x));
    }

    @Override
    public Group1Element invExp(ZpElement exp) {
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
        Group1ElementBLS381 that = (Group1ElementBLS381) o;
        return x.equals(that.x);
    }

}
