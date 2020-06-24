package pairingBN254;

import pairingInterfaces.Group1Element;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BN254.ECP;
import org.apache.milagro.amcl.BN254.PAIR;

public class Group1ElementBN254 implements Group1Element {

    ECP x;

    Group1ElementBN254(ECP x){
        this.x=x; //Copy?
    }

    @Override
    public Group1ElementBN254 mul(Group1Element el2) {
        if(!(el2 instanceof Group1ElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group1ElementBN254 e2=(Group1ElementBN254)el2;
        Group1ElementBN254 res=new Group1ElementBN254(new ECP(x));
        res.x.add(e2.x);
        return res;
    }

    @Override
    public Group1ElementBN254 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBN254))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBN254 e=(ZpElementBN254)exp;
        return new Group1ElementBN254(PAIR.G1mul(x,e.x));
    }

    @Override
    public Group1Element invExp(ZpElement exp) {
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
        Group1ElementBN254 that = (Group1ElementBN254) o;
        return x.equals(that.x);
    }

}
