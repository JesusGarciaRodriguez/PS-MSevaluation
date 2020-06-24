package pairingBLS461;

import pairingInterfaces.Group2Element;
import pairingInterfaces.Hash1;
import psmultisign.PSverfKey;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BLS461.BIG;
import org.apache.milagro.amcl.BLS461.ECP2;
import org.apache.milagro.amcl.HASH512;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Hash1BLS461 implements Hash1 {

    @Override
    public ZpElement[] hash(PSverfKey[] vks) {
        ZpElement[] t= new ZpElement[vks.length];
        for(int i=0;i<vks.length;i++)
            t[i]=hashVK(vks[i]);
        return t;
    }

    private ZpElement hashVK(PSverfKey vk) {
        if(!(vk.getVX() instanceof Group2ElementBLS461))
            throw new IllegalArgumentException("Elements must be BLS461"); //Suppose every element is from same class (they are constructed like that)
        Group2ElementBLS461 x=(Group2ElementBLS461)vk.getVX();
        Group2ElementBLS461 y_m=(Group2ElementBLS461)vk.getVY_m();
        Group2ElementBLS461 y_epoch=(Group2ElementBLS461)vk.getVY_epoch();
        byte[] b= ecp2ToBytes(x.x);
        b=append(b,ecp2ToBytes(y_m.x));
        b=append(b,ecp2ToBytes(y_epoch.x));
        for(Group2Element yi:vk.getVY().values()){ //For each must process the values always in the same order.
            append(b,ecp2ToBytes(((Group2ElementBLS461) yi).x));
        }
        return new ZpElementBLS461(hashModOrder(b));
    }


    /**
     * Turns an ECP2 into a byte array
     *
     * @param e The ECP2 to turn into bytes
     * @return A byte array representation of the ECP2
     */
    private static byte[] ecp2ToBytes(ECP2 e) {
        byte[] ret = new byte[4 * PairingBLS461.FIELD_BYTES];
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
        ret.mod(PairingBLS461.p);
        return ret;
    }
}
