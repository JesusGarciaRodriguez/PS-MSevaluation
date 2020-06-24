package unit;

import exceptions.MSSetupException;
import multisign.MS;
import multisign.MSauxArg;
import multisign.MSprivateKey;
import multisign.MSverfKey;
import org.apache.milagro.amcl.BN254.BIG;
import org.apache.milagro.amcl.BN254.CONFIG_BIG;
import org.apache.milagro.amcl.BN254.ROM;
import org.apache.milagro.amcl.RAND;
import org.junit.Test;
import pairingBN254.*;
import pairingInterfaces.*;
import psmultisign.PSauxArg;
import psmultisign.PSms;
import psmultisign.PSverfKey;
import unit.pairingMock.Group1ElementMock;
import unit.pairingMock.Group2ElementMock;
import unit.pairingMock.Group3ElementMock;
import unit.pairingMock.ZpElementMock;
import utils.Pair;

import java.util.*;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestBN254 {
	private static final BIG p=new BIG(ROM.CURVE_Order);
	private static final int FIELD_BYTES= CONFIG_BIG.MODBYTES;
    private static final String PAIRING_NAME="pairingBN254.PairingBuilderBN254";

    private Set<String> attrNames=new HashSet<>(Arrays.asList("name","age"));
    private int nServers=3;

    @Test
    public void testHash0(){
        int tamMessage=3;
        Hash0 h=new Hash0BN254();
        Collection<ZpElement> m1=new HashSet<>();
        Collection<ZpElement> m2=new HashSet<>();
        //Set specific seed for attribute generation
        int seedLength = FIELD_BYTES;
        RAND rng = new RAND();
        rng.clean();
        byte[] raw=new byte[seedLength];
        for (int i=0;i<seedLength;i++) raw[i]=(byte)(i);
        rng.seed(seedLength,raw);
        //Generate messages that will be hashed as random ZpElements.
        for(int i=0;i< tamMessage;i++){
            m1.add(new ZpElementBN254(BIG.randomnum(p, rng)));
        }
        for(int i=0;i< tamMessage;i++){
            m2.add(new ZpElementBN254(BIG.randomnum(p, rng)));
        }
        //Hashing
        Pair<ZpElement, Group1Element> hashM1_1=h.hash(m1);
        Pair<ZpElement, Group1Element> hashM2=h.hash(m2);
        Pair<ZpElement, Group1Element> hashM1_2=h.hash(m1);
        //Check hashes
        assertThat(hashM1_1.getFirst().equals(hashM1_2.getFirst()),is(true));
        assertThat(hashM1_1.getSecond().equals(hashM1_2.getSecond()),is(true));
        assertThat(hashM1_1.getFirst().equals(hashM2.getFirst()),is(false));
        assertThat(hashM1_1.getSecond().equals(hashM2.getSecond()),is(false));
    }

    @Test
    public void testHash1() throws MSSetupException {
//Create a PS-scheme instantiation
        MS psScheme=new PSms();
        //Generate auxArg and setup
        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
        psScheme.setup(nServers,auxArg);
        //KeyGeneration for three servers
        PSverfKey[] serverVK1=new PSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverVK1[i]=(PSverfKey)keys.getSecond();
        }
        //KeyGeneration for other three servers
        PSverfKey[] serverVK2=new PSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverVK2[i]=(PSverfKey)keys.getSecond();
        }
        //Check hashing
        Hash1 h1=new Hash1BN254();
        ZpElement[] t1_1=h1.hash(serverVK1);
        ZpElement[] t2=h1.hash(serverVK2);
        ZpElement[] t1_2=h1.hash(serverVK1);
        for(int i=0;i<nServers;i++){
            assertThat(t1_1[i].equals(t1_2[i]),is(true));
            assertThat(t1_1[i].equals(t2[i]),is(false));
        }
    }

    @Test
    public void testHash2() throws MSSetupException {
        //Create a PS-scheme instantiation
        MS psScheme=new PSms();
        //Generate auxArg and setup
        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
        psScheme.setup(nServers,auxArg);
        //KeyGeneration for three servers
        PSverfKey[] serverVK1=new PSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverVK1[i]=(PSverfKey)keys.getSecond();
        }
        PSverfKey avk1=(PSverfKey)psScheme.kAggr(serverVK1);
        //KeyGeneration for other three servers
        PSverfKey[] serverVK2=new PSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverVK2[i]=(PSverfKey)keys.getSecond();
        }
        PSverfKey avk2=(PSverfKey)psScheme.kAggr(serverVK2);
        //Create message
        String m="Test";
        //Create dummy group1 and 3 elements
        PairingBuilder builder=new PairingBuilderBN254();
        PairingBN254 pair=new PairingBN254();
        Group1Element sig1=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group1Element sig2=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group3Element prodT=pair.pair(builder.getGroup1Generator().exp(builder.getRandomZpElement()),builder.getGroup2Generator());
        Group3Element prodT2=pair.pair(builder.getGroup1Generator().exp(builder.getRandomZpElement()),builder.getGroup2Generator());
        //Check hashing
        Hash2 h2=new Hash2BN254();
        ZpElement res1_1=h2.hash(m,avk1,sig1,sig2,prodT);
        ZpElement res2=h2.hash(m,avk2,sig1,sig2,prodT);
        ZpElement res1_2=h2.hash(m,avk1,sig1,sig2,prodT);
        ZpElement res3=h2.hash(m,avk1,sig1,sig2,prodT2);
        ZpElement res4=h2.hash(m,avk1,sig1,sig1,prodT);
        ZpElement res5=h2.hash(m,avk1,sig2,sig2,prodT);
        ZpElement res6=h2.hash("Test2",avk1,sig1,sig2,prodT);
        assertThat(res1_1.equals(res1_2),is(true));
        assertThat(res1_1.equals(res2),is(false));
        assertThat(res1_1.equals(res3),is(false));
        assertThat(res1_1.equals(res4),is(false));
        assertThat(res1_1.equals(res5),is(false));
        assertThat(res1_1.equals(res6),is(false));
        //Create dummy message
        String m2="Test2";
        assertThat(h2.hash(m,avk1,sig1,sig2,prodT).equals(h2.hash(m2,avk1,sig1,sig2,prodT)),is(false));

    }

    @Test
    public void testPairing() {
        PairingBuilder builder=new PairingBuilderBN254();
        PairingBN254 pair=new PairingBN254();
        Group1Element g1=builder.getGroup1Generator();
        Group2Element g2=builder.getGroup2Generator();
        ZpElement a=builder.getRandomZpElement();
        ZpElement b=builder.getRandomZpElement();
        ZpElement c=builder.getRandomZpElement();
        ZpElement d=builder.getRandomZpElement();

        assertThat(pair.pair(g1,g2).equals(pair.pair(g1,g2)),is(true));
        assertThat(pair.pair(g1.exp(a),g2).equals(pair.pair(g1,g2).exp(a)),is(true));
        assertThat(pair.pair(g1,g2.exp(b)).equals(pair.pair(g1,g2).exp(b)),is(true));
        assertThat(pair.pair(g1.exp(c),g2.exp(d)).equals(pair.pair(g1,g2).exp(c.mul(d))),is(true));
    }

    @Test
    public void testMultiPairing() {
        PairingBuilder builder=new PairingBuilderBN254();
        PairingBN254 pair=new PairingBN254();
        Group1Element g1=builder.getGroup1Generator();
        Group2Element g2=builder.getGroup2Generator();
        ZpElement a=builder.getRandomZpElement();
        ZpElement b=builder.getRandomZpElement();
        ZpElement c=builder.getRandomZpElement();
        ZpElement d=builder.getRandomZpElement();
        Group1Element el1a=g1.exp(a);
        Group1Element el1c=g1.exp(c);
        Group2Element el2b=g2.exp(b);
        Group2Element el2d=g2.exp(d);
        Group3Element res1=pair.pair(el1a,el2b).mul(pair.pair(el1c,el2d));
        Collection<Pair<Group1Element,Group2Element>> elements=new LinkedList<>();
        elements.add(new Pair<>(el1a,el2b));
        elements.add(new Pair<>(el1c,el2d));
        Group3Element res2=pair.multiPair(elements);
        assertThat(res1.equals(res2),is(true));
    }

    @Test
    public void testInvExpGroup1() {
        PairingBuilder builder=new PairingBuilderBN254();
        int numberOfTests=10;
        Group1Element g1=builder.getGroup1Generator();
        ZpElement r=builder.getRandomZpElement();
        g1=g1.exp(r);
        for(int i=0;i<numberOfTests;i++) {
            ZpElement a = builder.getRandomZpElement();
            assertThat(g1.exp(a).mul(g1.invExp(a)).isUnity(), is(true));
        }
    }

    @Test
    public void testInvExpGroup2() {
        PairingBuilder builder=new PairingBuilderBN254();
        int numberOfTests=10;
        Group2Element g2=builder.getGroup2Generator();
        ZpElement r=builder.getRandomZpElement();
        g2=g2.exp(r);
        for(int i=0;i<numberOfTests;i++) {
            ZpElement a = builder.getRandomZpElement();
            assertThat(g2.exp(a).mul(g2.invExp(a)).isUnity(), is(true));
        }
    }

    @Test
    public void testInvExpGroup3() {
        PairingBuilder builder=new PairingBuilderBN254();
        int numberOfTests=10;
        Group3Element g3=builder.getGroup3Generator();
        ZpElement r=builder.getRandomZpElement();
        g3=g3.exp(r);
        for(int i=0;i<numberOfTests;i++) {
            ZpElement a = builder.getRandomZpElement();
            assertThat(g3.exp(a).mul(g3.invExp(a)).isUnity(), is(true));
        }
    }

    @Test
    public void testInverseOverZp() {
        PairingBuilder builder=new PairingBuilderBN254();
        int numberOfTests=10;
        for(int i=0;i<numberOfTests;i++){
            ZpElement r=builder.getRandomZpElement();
            ZpElement rInv=r.inverse();
            assertThat( r.mul(rInv).isUnity(), is(true));
        }
    }

    @Test
    public void testInverseZpWithGroup1() {
        PairingBuilder builder=new PairingBuilderBN254();
        Group1Element t=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        int numberOfTests=10;
        for(int i=0;i<numberOfTests;i++){
            ZpElement r=builder.getRandomZpElement();
            ZpElement rInv=r.inverse();
            assertThat( t.exp(r).exp(rInv).equals(t), is(true));
        }
    }

    @Test
    public void testInverseZpWithGroup2() {
        PairingBuilder builder=new PairingBuilderBN254();
        Group2Element t=builder.getGroup2Generator().exp(builder.getRandomZpElement());
        int numberOfTests=10;
        for(int i=0;i<numberOfTests;i++){
            ZpElement r=builder.getRandomZpElement();
            ZpElement rInv=r.inverse();
            assertThat( t.exp(r).exp(rInv).equals(t), is(true));
        }
    }

    @Test
    public void testInverseZpWithGroup3() {
        PairingBuilder builder=new PairingBuilderBN254();
        Group3Element t=builder.getGroup3Generator().exp(builder.getRandomZpElement());
        int numberOfTests=10;
        for(int i=0;i<numberOfTests;i++){
            ZpElement r=builder.getRandomZpElement();
            ZpElement rInv=r.inverse();
            assertThat( t.exp(r).exp(rInv).equals(t), is(true));
        }
    }

    @Test
    public void testArgumentExceptionsGroup1Element(){
        Group1Element g=(new PairingBuilderBN254()).getGroup1Generator();
        Group1Element mockG=new Group1ElementMock();
        ZpElement mockZ=new ZpElementMock();
        try{
            g.mul(mockG);
            fail("Multiplication should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.exp(mockZ);
            fail("Exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.invExp(mockZ);
            fail("Inverse exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testEqualsGroup1Element(){
        PairingBuilder builder=new PairingBuilderBN254();
        Group1Element g1=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group1Element g2=g1.mul(g1);
        assertThat(g1.equals(g1), is(true));
        assertThat(g1.equals(g2), is(false));
        assertThat(g1.equals(null), is(false));
        assertThat(g1.equals(new Group1ElementMock()), is(false));
    }

    @Test
    public void testArgumentExceptionsGroup2Element(){
        Group2Element g=(new PairingBuilderBN254()).getGroup2Generator();
        Group2Element mockG=new Group2ElementMock();
        ZpElement mockZ=new ZpElementMock();
        try{
            g.mul(mockG);
            fail("Multiplication should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.exp(mockZ);
            fail("Exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.invExp(mockZ);
            fail("Inverse exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testEqualsGroup2Element(){
        PairingBuilder builder=new PairingBuilderBN254();
        Group2Element g1=builder.getGroup2Generator().exp(builder.getRandomZpElement());
        Group2Element g2=g1.mul(g1);
        assertThat(g1.equals(g1), is(true));
        assertThat(g1.equals(g2), is(false));
        assertThat(g1.equals(null), is(false));
        assertThat(g1.equals(new Group2ElementMock()), is(false));

    }

    @Test
    public void testArgumentExceptionsGroup3Element(){
        Group3Element g=(new PairingBuilderBN254()).getGroup3Generator();
        Group3Element mockG=new Group3ElementMock();
        ZpElement mockZ=new ZpElementMock();
        try{
            g.mul(mockG);
            fail("Multiplication should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.exp(mockZ);
            fail("Exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.invExp(mockZ);
            fail("Inverse exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testEqualsGroup3Element(){
        PairingBuilder builder=new PairingBuilderBN254();
        Group3Element g1=builder.getGroup3Generator().exp(builder.getRandomZpElement());
        Group3Element g2=g1.mul(g1);
        assertThat(g1.equals(g1), is(true));
        assertThat(g1.equals(g2), is(false));
        assertThat(g1.equals(null), is(false));
        assertThat(g1.equals(new Group3ElementMock()), is(false));
    }

    @Test
    public void testArgumentExceptionsZpElement(){
        ZpElement z=(new PairingBuilderBN254()).getRandomZpElement();
        ZpElement mockZ=new ZpElementMock();
        try{
            z.add(mockZ);
            fail("Addition should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            z.mul(mockZ);
            fail("Multiplication should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            z.sub(mockZ);
            fail("Subtraction should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testEqualsZpElement(){
        PairingBuilder builder=new PairingBuilderBN254();
        ZpElement z1=builder.getRandomZpElement();
        ZpElement z2=z1.add(z1);
        assertThat(z1.equals(z1), is(true));
        assertThat(z1.equals(z2), is(false));
        assertThat(z1.equals(null), is(false));
        assertThat(z1.equals(new ZpElementMock()), is(false));
    }


    @Test(expected=IllegalArgumentException.class)
    public void testArgumentExceptionsHash0(){
        Hash0 h=(new PairingBuilderBN254()).getHash0();
        Collection<ZpElement> elements=new LinkedList<>();
        elements.add(new ZpElementMock());
        h.hash(elements);
        fail();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testArgumentExceptionsHash1(){
        Hash1 h=(new PairingBuilderBN254()).getHash1();
        Group2Element mockG=new Group2ElementMock();
        PSverfKey vk=new PSverfKey(mockG,null,null,null);
        PSverfKey[] vks=new PSverfKey[1];
        vks[0]=vk;
        h.hash(vks);
        fail();
    }



    @Test
    public void testArgumentExceptionsHash2(){
        Hash2 h=(new PairingBuilderBN254()).getHash2();
        Group1Element g1=(new PairingBuilderBN254()).getGroup1Generator();
        Group1Element mockG1=new Group1ElementMock();
        Group1Element g2=(new PairingBuilderBN254()).getGroup1Generator();
        Group1Element mockG2=new Group1ElementMock();
        Group3Element g3=(new PairingBuilderBN254()).getGroup3Generator();
        Group3Element mockG3=new Group3ElementMock();
        PSverfKey vk=new PSverfKey(new Group2ElementMock(),null,null,null);
        String m="test";
        try{
            h.hash(m,vk,mockG1,g2,g3);
            fail("Should throw IllegalArgumentException, sigma1");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,mockG2,g3);
            fail("Should throw IllegalArgumentException, sigma2");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,g2,mockG3);
            fail("Should throw IllegalArgumentException, prodT");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,g2,g3);
            fail("Should throw IllegalArgumentException, prodT");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testArgumentExceptionsPair(){
        Pairing pairing=(new PairingBuilderBN254()).getPairing();
        Group1Element g1=(new PairingBuilderBN254()).getGroup1Generator();
        Group1Element mockG1=new Group1ElementMock();
        Group2Element g2=(new PairingBuilderBN254()).getGroup2Generator();
        Group2Element mockG2=new Group2ElementMock();
        try{
            pairing.pair(g1,mockG2);
            fail("Should throw IllegalArgumentException, el2");
        }catch(IllegalArgumentException e){
        }
        try{
            pairing.pair(mockG1,g2);
            fail("Should throw IllegalArgumentException, el1");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testArgumentExceptionsMultiPair(){
        Pairing pairing=(new PairingBuilderBN254()).getPairing();
        Group1Element g1=(new PairingBuilderBN254()).getGroup1Generator();
        Group1Element mockG1=new Group1ElementMock();
        Group2Element g2=(new PairingBuilderBN254()).getGroup2Generator();
        Group2Element mockG2=new Group2ElementMock();
        Pair<Group1Element,Group2Element> good=new Pair<>(g1,g2);
        Pair<Group1Element,Group2Element> wrongG1=new Pair<>(mockG1,g2);
        Pair<Group1Element,Group2Element> wrongG2=new Pair<>(g1,mockG2);
        Collection<Pair<Group1Element,Group2Element>> wrong1=new LinkedList<>();
        wrong1.add(good);
        wrong1.add(wrongG1);
        Collection<Pair<Group1Element,Group2Element>> wrong2=new LinkedList<>();
        wrong2.add(good);
        wrong2.add(wrongG2);

        try{
            pairing.multiPair(wrong1);
            fail("Should throw IllegalArgumentException, el1");
        }catch(IllegalArgumentException e){
        }
        try{
            pairing.multiPair(wrong2);
            fail("Should throw IllegalArgumentException, el2");
        }catch(IllegalArgumentException e){
        }
    }
}
