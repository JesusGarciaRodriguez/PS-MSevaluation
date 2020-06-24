package pairingBLS461;

import pairingInterfaces.Group1Element;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BLS461.ECP;
import org.apache.milagro.amcl.BLS461.PAIR;

public class Group1ElementBLS461 implements Group1Element {

    ECP x;

    Group1ElementBLS461(ECP x){
        this.x=x; //Copy?
    }

    @Override
    public Group1ElementBLS461 mul(Group1Element el2) {
        if(!(el2 instanceof Group1ElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group1ElementBLS461 e2=(Group1ElementBLS461)el2;
        Group1ElementBLS461 res=new Group1ElementBLS461(new ECP(x));
        res.x.add(e2.x);
        return res;
    }

    @Override
    public Group1ElementBLS461 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)exp;
        return new Group1ElementBLS461(PAIR.G1mul(x,e.x));
    }

    @Override
    public Group1Element invExp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)exp;
        return this.exp(e.neg());
    }

    @Override
    public boolean isUnity() {
        return x.is_infinity();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Group1ElementBLS461 that = (Group1ElementBLS461) o;
        return x.equals(that.x);
    }

}
