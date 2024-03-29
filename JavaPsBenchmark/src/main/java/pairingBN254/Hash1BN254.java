package pairingBN254;

import pairingInterfaces.Group2Element;
import pairingInterfaces.Hash1;
import psmultisign.PSverfKey;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BN254.BIG;
import org.apache.milagro.amcl.BN254.ECP2;
import org.apache.milagro.amcl.HASH512;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Hash1BN254 implements Hash1 {

    @Override
    public ZpElement[] hash(PSverfKey[] vks) {
        ZpElement[] t= new ZpElement[vks.length];
        for(int i=0;i<vks.length;i++)
            t[i]=hashVK(vks[i]);
        return t;
    }

    private ZpElement hashVK(PSverfKey vk) {
        if(!(vk.getVX() instanceof Group2ElementBN254))
            throw new IllegalArgumentException("Elements must be BN254"); //Suppose every element is from same class (they are constructed like that)
        Group2ElementBN254 x=(Group2ElementBN254)vk.getVX();
        Group2ElementBN254 y_m=(Group2ElementBN254)vk.getVY_m();
        Group2ElementBN254 y_epoch=(Group2ElementBN254)vk.getVY_epoch();
        byte[] b= ecp2ToBytes(x.x);
        b=append(b,ecp2ToBytes(y_m.x));
        b=append(b,ecp2ToBytes(y_epoch.x));
        for(Group2Element yi:vk.getVY().values()){ //For each must process the values always in the same order.
            append(b,ecp2ToBytes(((Group2ElementBN254) yi).x));
        }
        return new ZpElementBN254(hashModOrder(b));
    }


    /**
     * Turns an ECP2 into a byte array
     *
     * @param e The ECP2 to turn into bytes
     * @return A byte array representation of the ECP2
     */
    private static byte[] ecp2ToBytes(ECP2 e) {
        byte[] ret = new byte[4 * PairingBN254.FIELD_BYTES];
        e.toBytes(ret);
        return ret;
    }

    /**
     * Appends a byte array to an existing byte array
     *
     * @param data     The data to which we want to append
     * @param toAppend The data to be appended
     * @return A new byte[] of data + toAppend
     */
    private static byte[] append(byte[] data, byte[] toAppend) {

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            stream.write(data);
            stream.write(toAppend);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return stream.toByteArray();
    }


    /**
     * Hashes bytes to an amcl.BIG
     * in 0, ..., GROUP_ORDER
     *
     * @param data The data to be hashed
     * @return A BIG in 0, ..., GROUP_ORDER-1 that is the hash of the data
     */
    private static BIG hashModOrder(byte[] data) {
        HASH512 hash = new HASH512();
        for (byte b : data) {
            hash.process(b);
        }
        byte[] hasheddata = hash.hash();

        BIG ret = BIG.fromBytes(hasheddata);
        ret.mod(PairingBN254.p);
        return ret;
    }
}
