package pairingBLS461;

import pairingInterfaces.Group2Element;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BLS461.ECP2;
import org.apache.milagro.amcl.BLS461.PAIR;

public class Group2ElementBLS461 implements Group2Element {

    ECP2 x;

    Group2ElementBLS461(ECP2 x){
        this.x=x;//Copy?
    }

    @Override
    public Group2ElementBLS461 mul(Group2Element el2) {
        if(!(el2 instanceof Group2ElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group2ElementBLS461 e2=(Group2ElementBLS461)el2;
        Group2ElementBLS461 res=new Group2ElementBLS461(new ECP2(x));
        res.x.add(e2.x);
        return res;
    }

    @Override
    public Group2ElementBLS461 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)exp;
        return new Group2ElementBLS461(PAIR.G2mul(x,e.x));
    }

    @Override
    public Group2Element invExp(ZpElement exp) {
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
        Group2ElementBLS461 that = (Group2ElementBLS461) o;
        return x.equals(that.x);
    }

}
