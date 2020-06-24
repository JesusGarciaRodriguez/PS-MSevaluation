package unit;

import exceptions.MSSetupException;
import multisign.*;
import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.CONFIG_BIG;
import org.apache.milagro.amcl.BLS381.ROM;
import org.apache.milagro.amcl.RAND;
import org.junit.Test;
import pairingBLS381.PairingBuilderBLS381;
import pairingBLS381.ZpElementBLS381;
import pairingInterfaces.Group1Element;
import pairingInterfaces.PairingBuilder;
import pairingInterfaces.ZpElement;
import psmultisign.*;
import unit.multisingMock.*;
import utils.Pair;

import java.util.*;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;


public class TestPSsignBLS381 {

	private static final BIG p=new BIG(ROM.CURVE_Order);
	private static final int FIELD_BYTES= CONFIG_BIG.MODBYTES;
	private static final String PAIRING_NAME="pairingBLS381.PairingBuilderBLS381";

	private Set<String> attrNames=new HashSet<>(Arrays.asList("name","age"));
	private int nServers=3;


	@Test
	public void testCompletePSFlow() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggr(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK,signShares);
		//Verifying the signature
		assertThat(psScheme.verf(avk,mAttr,signature), is(true));
		//Revealed attributes and signed message
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		Map<String,ZpElement> revAttr=new HashMap<>();
		for(String attr:revealedAttributesNames)
			revAttr.put(attr,attributes.get(attr));
		MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
		String message="TestMessage";
		//Token generation
		MSzkToken token=psScheme.presentZKtoken(avk,revealedAttributesNames,mAttr,message,signature);
		//Token verification
		assertThat(psScheme.verifyZKtoken(token,avk,message,mRevealAttr),is(true));
	}


	@Test
	public void testDifferentAttributesVerify() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte)(i*i);
		rng.seed(seedLength,raw);
		//Generate attributes and epoch as random ZpElements.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggr(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage m=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],m);
		}
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK,signShares);
		//Creating new attributes
		Map<String, ZpElement> wrongAttributes=new HashMap<>();
		for(String attr:attrNames){
			wrongAttributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		//Creating message from falsified attributes
		MSmessage wrongM=new PSmessage(wrongAttributes,epoch);
		//Verifying the signature
		assertThat(psScheme.verf(avk,wrongM,signature), is(false));
	}

	@Test(expected=IllegalArgumentException.class)
	public void testNotEnoughServersComb() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte)(i*i);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggr(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage m=new PSmessage(attributes,epoch);
		//Signature share for each server (except one)
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers-1;i++){
			signShares[i]=psScheme.sign(serverSK[i],m);
		}
		//Combining shares in one signature
		psScheme.comb(serverVK,signShares);
		fail();
	}

	@Test
	public void testWrongEpoch() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte)(i*i);
		rng.seed(seedLength,raw);
		//Generate attributes and epoch as random ZpElements.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggr(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage m=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],m);
		}
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK,signShares);
		//Creating new attributes
		ZpElement wrongEpoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Creating message from falsified attributes
		MSmessage wrongM=new PSmessage(attributes,wrongEpoch);
		//Verifying the signature
		assertThat(psScheme.verf(avk,wrongM,signature), is(false));
		assertThat(psScheme.verf(avk,m,signature), is(true));
		//Revealed attributes and signed message
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		Map<String,ZpElement> revAttr=new HashMap<>();
		for(String attr:revealedAttributesNames)
			revAttr.put(attr,attributes.get(attr));
		MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
		String message="TestMessage";
		//Token generation
		MSzkToken token=psScheme.presentZKtoken(avk,revealedAttributesNames,m,message,signature);
		MSzkToken tokenWrongEpoch=psScheme.presentZKtoken(avk,revealedAttributesNames,m,message,signature);
		//Token verification
		assertThat(psScheme.verifyZKtoken(token,avk,message,mRevealAttr),is(true));
		assertThat(psScheme.verifyZKtoken(tokenWrongEpoch,avk,message,new PSmessage(revAttr,wrongEpoch)),is(false));
	}

	@Test()
	public void testVerfKeyEquals() throws MSSetupException {
		int n=2;
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(n,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[n];
		MSverfKey[] serverVK=new MSverfKey[n];
		for(int i=0;i<n;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		MSverfKey vk0=serverVK[0];
		assertThat(vk0.equals(serverVK[0]), is(true));
		assertThat(vk0.equals(serverVK[1]), is(false));
		assertThat(vk0.equals(serverSK[0]), is(false));
	}

	@Test()
	public void testNoSetup() {
		MS psScheme=new PSms();
		try{
			psScheme.kg();
			fail("Should throw IllegalStateException, keyGen");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.kAggr(null);
			fail("Should throw IllegalStateException, keyGen");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.sign(null,null);
			fail("Should throw IllegalStateException, keyAggr");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.comb(null,null);
			fail("Should throw IllegalStateException, comb");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.verf(null,null,null);
			fail("Should throw IllegalStateException, comb");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.presentZKtoken(null,null,null,null,null);
			fail("Should throw IllegalStateException, presentZKtoken");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.verifyZKtoken(null,null,null,null);
			fail("Should throw IllegalStateException, verifyZKtoken");
		}catch (IllegalStateException e){
		}
	}


	@Test()
	public void testSetupExceptions() throws MSSetupException {
		MS psScheme=new PSms();
		int n=nServers;
		int wrongN=0;
		PSauxArg correctAux=new PSauxArg(PAIRING_NAME,attrNames);
		PSauxArg wrongPairingName=new PSauxArg("NoName",attrNames);
		PSauxArg wrongAttrNames=new PSauxArg(PAIRING_NAME,new HashSet<>());
		PSauxArg wrongAttrNames2=new PSauxArg(PAIRING_NAME,null);
		try{
			psScheme.setup(n,new MockAuxArg());
			fail("Should throw IllegalArgumentException, wrong psauxarg");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.setup(wrongN,correctAux);
			fail("Should throw MSSetupException, wrong N");
		}catch (MSSetupException e){
		}
		try{
			psScheme.setup(n,wrongPairingName);
			fail("Should throw MSSetupException, wrongPairingName");
		}catch (MSSetupException e){
		}
		try{
			psScheme.setup(n,wrongAttrNames);
			fail("Should throw MSSetupException, length0 attrnames");
		}catch (MSSetupException e){
		}
		try{
			psScheme.setup(n,wrongAttrNames2);
			fail("Should throw MSSetupException, null attrnames");
		}catch (MSSetupException e){
		}
		try{
			psScheme.setup(n,correctAux);
			psScheme.setup(n,correctAux);
			fail("Should throw IllegalStateException");
		}catch (IllegalStateException e){
		}
	}

	@Test()
	public void testKAggrExceptions() throws MSSetupException {
		int n1=2;
		int n2=3;
		//Create scheme for 2 severs with attrNames name, age; and get verification key
		MS psScheme1=new PSms();
		PSauxArg auxArg1=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme1.setup(n1,auxArg1);
		PSverfKey vk1=(PSverfKey)psScheme1.kg().getSecond();
		//Create scheme for 3 severs with attrNames test; and get verification key
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(n2,auxArg2);
		PSverfKey vk2=(PSverfKey)psScheme2.kg().getSecond();
		//Create arrays of verfKeys:
		MSverfKey[] wrongType=new MSverfKey[2];
		wrongType[0]=vk1;
		wrongType[1]=new MockVerfKey();
		MSverfKey[] wrongFirstVk=new MSverfKey[2];
		wrongFirstVk[0]=vk2;
		wrongFirstVk[1]=vk1;
		MSverfKey[] wrongSecondVk=new MSverfKey[2];
		wrongSecondVk[0]=vk1;
		wrongSecondVk[1]=vk2;
		//Check exceptions for wrong type, wrong number of vks, wrong att of vks
		try{
			psScheme1.kAggr(wrongType);
			fail("Should throw IllegalArgumentException, type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme2.kAggr(new MSverfKey[1]);
			fail("Should throw IllegalArgumentException, number of vks");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.kAggr(wrongFirstVk);
			fail("Should throw MSSetupException,  wrong attr first");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.kAggr(wrongSecondVk);
			fail("Should throw IllegalStateException, wrong attr second");
		}catch (IllegalArgumentException e){
		}
	}

	@Test()
	public void testSignExceptions() throws MSSetupException {
		//Create scheme with attrNames name, age; and get secret key
		MS psScheme1=new PSms();
		PSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme1.setup(nServers,auxArg);
		PSprivateKey sk1=(PSprivateKey) psScheme1.kg().getFirst();
		//Create scheme with attrNames test; and get secret key
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(nServers,auxArg2);
		PSprivateKey sk2=(PSprivateKey) psScheme2.kg().getFirst();
		//Create scheme with attrNames test1,test2; and get secret key
		MS psScheme3=new PSms();
		PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test1","test2")));
		psScheme3.setup(nServers,auxArg3);
		PSprivateKey sk3=(PSprivateKey) psScheme3.kg().getFirst();
		//Generate correct message
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		MSmessage correctMsg=new PSmessage(attributes,epoch);
		//Generate wrong messages
		Map<String, ZpElement> attributes2=new HashMap<>();
		attributes2.put("test",new ZpElementBLS381(BIG.randomnum(p, rng)));
		MSmessage wrongNattrMsg=new PSmessage(attributes2,epoch);
		Map<String, ZpElement> attributes3=new HashMap<>();
		attributes3.put("test1",new ZpElementBLS381(BIG.randomnum(p, rng)));
		attributes3.put("test2",new ZpElementBLS381(BIG.randomnum(p, rng)));
		MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);

		//Check exceptions for wrong types, wrong number number of attr and wrong attrNames for sk and msg
		try{
			psScheme1.sign(new MockPrivateKey(),correctMsg);
			fail("Should throw IllegalArgumentException, type sk");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.sign(sk1,new MockMessage());
			fail("Should throw IllegalArgumentException, type msg");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.sign(sk2,correctMsg);
			fail("Should throw IllegalArgumentException, type msg");
		}catch (IllegalArgumentException e){
		}try{
			psScheme1.sign(sk3,correctMsg);
			fail("Should throw IllegalArgumentException, type msg");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.sign(sk1,wrongAttrNamesMsg);
			fail("Should throw IllegalArgumentException, attr names msg");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.sign(sk1,wrongNattrMsg);
			fail("Should throw IllegalArgumentException, number attr msg");
		}catch (IllegalArgumentException e){
		}
	}

	@Test()
	public void testCombExceptions() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Construct invalid vks and signature share
		MSverfKey[] serverVKWrong1=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			serverVKWrong1[i]=serverVK[i];
		}
		serverVKWrong1[nServers-1]=new MockVerfKey();
		MSverfKey[] serverVKWrong2=new MSverfKey[nServers+1];
		MSsignature[] signSharesWrong1=new MSsignature[nServers];
		for(int i=0;i<nServers-1;i++){
			signSharesWrong1[i]=signShares[i];
		}
		signSharesWrong1[nServers-1]=new PSsignature(new PairingBuilderBLS381().getRandomZpElement(),((PSsignature)signShares[nServers-1]).getSigma1(),((PSsignature)signShares[nServers-1]).getSigma2());
		MSsignature[] signSharesWrong2=new MSsignature[nServers];
		for(int i=0;i<nServers-1;i++){
			signSharesWrong2[i]=signShares[i];
		}
		signSharesWrong2[nServers-1]=new PSsignature(((PSsignature)signShares[nServers-1]).getMPrim(),new PairingBuilderBLS381().getGroup1Generator(),((PSsignature)signShares[nServers-1]).getSigma2());
		MSsignature[] signSharesWrong3=new MSsignature[nServers+1];
		MSsignature[] signSharesWrong4=new MSsignature[nServers+1];
		for(int i=0;i<nServers-1;i++){
			signSharesWrong4[i]=signShares[i];
		}
		signSharesWrong4[nServers-1]=new MockSignature();

		//Check exceptions for wrong types, wrong number of signatures/verification keys and incompatible signs.
		try{
			psScheme.comb(serverVKWrong1,signShares);
			fail("Should throw IllegalArgumentException, vk wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.comb(serverVKWrong2,signShares);
			fail("Should throw IllegalArgumentException, vks wrong length");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.comb(serverVK,signSharesWrong1);
			fail("Should throw IllegalArgumentException, signatures wrong mPrim");
		}catch (IllegalArgumentException e){
		}try{
			psScheme.comb(serverVK,signSharesWrong2);
			fail("Should throw IllegalArgumentException, signatures wrong sigma1");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.comb(serverVK,signSharesWrong3);
			fail("Should throw IllegalArgumentException, signatures wrong length");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.comb(serverVK,signSharesWrong4);
			fail("Should throw IllegalArgumentException, signatures wrong type");
		}catch (IllegalArgumentException e){
		}
	}


	@Test()
	public void testVerfFraudulentUnitySignature() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggr(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK,signShares);
		PairingBuilder pb=new PairingBuilderBLS381();
		ZpElement a=pb.getRandomZpElement();
		Group1Element unity=pb.getGroup1Generator().exp(a).mul(pb.getGroup1Generator().invExp(a));
		MSsignature signatureWrong=new PSsignature(((PSsignature)signature).getMPrim(),unity,unity);
		assertThat(psScheme.verf(avk,mAttr,signature),is(true));
		assertThat(psScheme.verf(avk,mAttr,signatureWrong),is(false));
	}

	@Test()
	public void testVerfExceptions() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggr(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK,signShares);
		//Construct invalid avk, message, signature
		Map<String, ZpElement> attributes2=new HashMap<>();
		attributes2.put("test",new ZpElementBLS381(BIG.randomnum(p, rng)));
		MSmessage wrongNattrMsg=new PSmessage(attributes2,epoch);
		Map<String, ZpElement> attributes3=new HashMap<>();
		attributes3.put("test1",new ZpElementBLS381(BIG.randomnum(p, rng)));
		attributes3.put("test2",new ZpElementBLS381(BIG.randomnum(p, rng)));
		MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(nServers,auxArg2);
		MSverfKey vkWrong1= psScheme2.kg().getSecond();
		MS psScheme3=new PSms();
		PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test1","test2")));
		psScheme3.setup(nServers,auxArg3);
		MSverfKey vkWrong2=psScheme3.kg().getSecond();
		//Check exceptions for wrong types, wrong number of signatures/verification keys.
		try{
			psScheme.verf(vkWrong1,mAttr,signature);
			fail("Should throw IllegalArgumentException, vk wrong number of attr");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(vkWrong2,mAttr,signature);
			fail("Should throw IllegalArgumentException, vk wrong attr names");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(new MockVerfKey(),mAttr,signature);
			fail("Should throw IllegalArgumentException, vk wrong type");
		}catch (IllegalArgumentException e){
		}try{
			psScheme.verf(avk,mAttr,new MockSignature());
			fail("Should throw IllegalArgumentException, signature wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(avk,wrongAttrNamesMsg,signature);
			fail("Should throw IllegalArgumentException, message wrong attr names");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(avk,wrongNattrMsg,signature);
			fail("Should throw IllegalArgumentException, message wrong attr length");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(avk,new MockMessage(),signature);
			fail("Should throw IllegalArgumentException, message wrong type");
		}catch (IllegalArgumentException e){
		}
	}

	@Test()
	public void testZkPresentExceptions() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggr(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK,signShares);
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		String message="TestMessage";
		//Token generation
		//Construct invalid avk, message, signature
		Map<String, ZpElement> attributes2=new HashMap<>();
		attributes2.put("test",new ZpElementBLS381(BIG.randomnum(p, rng)));
		MSmessage wrongNattrMsg=new PSmessage(attributes2,epoch);
		Map<String, ZpElement> attributes3=new HashMap<>();
		attributes3.put("test1",new ZpElementBLS381(BIG.randomnum(p, rng)));
		attributes3.put("test2",new ZpElementBLS381(BIG.randomnum(p, rng)));
		MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(nServers,auxArg2);
		MSverfKey vkWrong1= psScheme2.kg().getSecond();
		MS psScheme3=new PSms();
		PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test1","test2")));
		psScheme3.setup(nServers,auxArg3);
		MSverfKey vkWrong2=psScheme3.kg().getSecond();
		Set<String> revealedAttributesNamesWrong=new HashSet<>();
		revealedAttributesNamesWrong.add("testWrong");
		//Check exceptions for wrong types, wrong number of signatures/verification keys.
		try{
			psScheme.presentZKtoken(vkWrong1,revealedAttributesNames,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, vk wrong number of attr");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(vkWrong2,revealedAttributesNames,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, vk wrong attr names");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(new MockVerfKey(),revealedAttributesNames,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, vk wrong type");
		}catch (IllegalArgumentException e){
		}try{
			psScheme.presentZKtoken(avk,revealedAttributesNames,mAttr,message,new MockSignature());
			fail("Should throw IllegalArgumentException, signature wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(avk,revealedAttributesNames,wrongAttrNamesMsg,message,signature);
			fail("Should throw IllegalArgumentException, message wrong attr names");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(avk,revealedAttributesNames,wrongNattrMsg,message,signature);
			fail("Should throw IllegalArgumentException, message wrong attr length");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(avk,revealedAttributesNames,new MockMessage(),message,signature);
			fail("Should throw IllegalArgumentException, message wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(avk,revealedAttributesNamesWrong,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, wrong revealed attributes");
		}catch (IllegalArgumentException e){
		}
	}




	@Test()
	public void testZkVerifyFraudulentTokenRevealedAttributes() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggr(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK,signShares);
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		Map<String,ZpElement> revAttr=new HashMap<>();
		for(String attr:revealedAttributesNames)
			revAttr.put(attr,attributes.get(attr));
		MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
		String message="TestMessage";
		//Token generation
		MSzkToken token=psScheme.presentZKtoken(avk,revealedAttributesNames,mAttr,message,signature);
		//Construct invalid tokens
		PSzkToken psToken=(PSzkToken)token;
		Map<String,ZpElement> map1=new HashMap<>(psToken.getV_aj());
		map1.put("age",epoch);
		MSzkToken tokenWrong1=new PSzkToken(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map1,psToken.getV_t(),psToken.getV_aPrim());
		Map<String,ZpElement> map2=new HashMap<>(psToken.getV_aj());
		map2.remove("name");
		MSzkToken tokenWrong2=new PSzkToken(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map2,psToken.getV_t(),psToken.getV_aPrim());
		assertThat(psScheme.verifyZKtoken(tokenWrong1,avk,message,mRevealAttr),is(false));
		assertThat(psScheme.verifyZKtoken(tokenWrong2,avk,message,mRevealAttr),is(false));
	}


	@Test()
	public void testZkVerifyExceptions() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS381(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS381(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggr(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK,signShares);
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		Map<String,ZpElement> revAttr=new HashMap<>();
		for(String attr:revealedAttributesNames)
			revAttr.put(attr,attributes.get(attr));
		MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
		String message="TestMessage";
		//Token generation
		MSzkToken token=psScheme.presentZKtoken(avk,revealedAttributesNames,mAttr,message,signature);
		//Construct invalid avk, message, signature
		Map<String, ZpElement> attributes3=new HashMap<>();
		attributes3.put("test1",new ZpElementBLS381(BIG.randomnum(p, rng)));
		attributes3.put("test2",new ZpElementBLS381(BIG.randomnum(p, rng)));
		MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(nServers,auxArg2);
		MSverfKey vkWrong1= psScheme2.kg().getSecond();
		MS psScheme3=new PSms();
		PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test1","test2")));
		psScheme3.setup(nServers,auxArg3);
		MSverfKey vkWrong2=psScheme3.kg().getSecond();
		MS psScheme4=new PSms();
		PSauxArg auxArg4=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("name","test2")));
		psScheme4.setup(nServers,auxArg4);
		MSverfKey vkWrong3=psScheme4.kg().getSecond();
		Set<String> revealedAttributesNamesWrong=new HashSet<>();
		revealedAttributesNamesWrong.add("testWrong");
		PSzkToken psToken=(PSzkToken)token;
		Map<String,ZpElement> map1=new HashMap<>(psToken.getV_aj());
		map1.put("testWrong",epoch);
		MSzkToken tokenWrong1=new PSzkToken(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map1,psToken.getV_t(),psToken.getV_aPrim());
		Map<String,ZpElement> map2=new HashMap<>(psToken.getV_aj());
		map2.put("name",epoch);
		MSzkToken tokenWrong2=new PSzkToken(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map2,psToken.getV_t(),psToken.getV_aPrim());
		Map<String,ZpElement> map3=new HashMap<>(psToken.getV_aj());
		map3.remove("age");
		MSzkToken tokenWrong3=new PSzkToken(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map3,psToken.getV_t(),psToken.getV_aPrim());

		//Check exceptions for wrong types, wrong number of signatures/verification keys.
		try{
			psScheme.verifyZKtoken(token,vkWrong1,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, vk wrong number of attr");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(token,vkWrong2,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, vk wrong attr names hidden");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(token,vkWrong3,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, vk wrong attr names revealed");
		}catch (IllegalArgumentException e){
			e.printStackTrace();
		}
		try{
			psScheme.verifyZKtoken(token,new MockVerfKey(),message,mRevealAttr);
			fail("Should throw IllegalArgumentException, vk wrong type");
		}catch (IllegalArgumentException e){
		}try{
			psScheme.verifyZKtoken(new MockZkToken(),avk,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, token wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(token,avk,message,new MockMessage());
			fail("Should throw IllegalArgumentException, message type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(token,avk,message,wrongAttrNamesMsg);
			fail("Should throw IllegalArgumentException, message wrong attributes");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(tokenWrong1,avk,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, token invalid attr");
		}catch (IllegalArgumentException e){
		}
	}

}
