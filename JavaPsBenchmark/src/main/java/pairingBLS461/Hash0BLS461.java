package pairingBLS461;

import utils.Pair;
import pairingInterfaces.Group1Element;
import pairingInterfaces.Hash0;
import pairingInterfaces.ZpElement;
import org.apache.milagro.amcl.BLS461.BIG;
import org.apache.milagro.amcl.BLS461.ECP;
import org.apache.milagro.amcl.HASH512;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;

public class Hash0BLS461 implements Hash0 {

    @Override
    public Pair<ZpElement, Group1Element> hash(Collection<ZpElement> m) {
        byte [] b=new byte[0];
        for(ZpElement mi: m) {
            if(!(mi instanceof ZpElementBLS461))
                throw new IllegalArgumentException("Argument must be collection of ZpElementBLS461");
            b=append(b, bigToBytes(((ZpElementBLS461)mi).x));
        }
        ZpElement mPrim=new ZpElementBLS461(hashModOrder(b));
        Group1Element h=new Group1ElementBLS461(hashECP(b));
        return new Pair<>(mPrim,h);
    }


    /**
     * Hashes bytes to an amcl.BIG
     * in 0, ..., GROUP_ORDER-1
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

    /**
     *  Hashes bytes to an amcl.ECP
     *
     * @param data The data to be hashed
     * @return A ECP element
     */
    private static ECP hashECP(byte[] data) {
        HASH512 hash = new HASH512();
        for (byte b : data) {
            hash.process(b);
        }
        byte[] hasheddata = hash.hash();
        return ECP.mapit(hasheddata);
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
     * Turns a BIG into a byte array
     *
     * @param big The BIG to turn into bytes
     * @return A byte array representation of the BIG
     */
    private static byte[] bigToBytes(BIG big) {
        byte[] ret = new byte[PairingBLS461.FIELD_BYTES];
        big.toBytes(ret);
        return ret;
    }
}
