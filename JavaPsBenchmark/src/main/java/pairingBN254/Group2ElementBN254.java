package pairingBN254;

import pairingInterfaces.Group2Element;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BN254.ECP2;
import org.apache.milagro.amcl.BN254.PAIR;

public class Group2ElementBN254 implements Group2Element {

    ECP2 x;

    Group2ElementBN254(ECP2 x){
        this.x=x;//Copy?
    }

    @Override
    public Group2ElementBN254 mul(Group2Element el2) {
        if(!(el2 instanceof Group2ElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group2ElementBN254 e2=(Group2ElementBN254)el2;
        Group2ElementBN254 res=new Group2ElementBN254(new ECP2(x));
        res.x.add(e2.x);
        return res;
    }

    @Override
    public Group2ElementBN254 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBN254 e=(ZpElementBN254)exp;
        return new Group2ElementBN254(PAIR.G2mul(x,e.x));
    }

    @Override
    public Group2Element invExp(ZpElement exp) {
        if(!(exp instanceof ZpElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBN254 e=(ZpElementBN254)exp;
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
        Group2ElementBN254 that = (Group2ElementBN254) o;
        return x.equals(that.x);
    }

}
