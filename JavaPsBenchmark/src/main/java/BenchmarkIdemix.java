import abce.net.URI;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.ibm.zurich.idmx.buildingBlock.pseudonym.PseudonymBuildingBlock;
import com.ibm.zurich.idmx.buildingBlock.pseudonym.scopeExclusive.ScopeExclusivePseudonymBuildingBlock;
import com.ibm.zurich.idmx.buildingBlock.pseudonym.standard.StandardPseudonymBuildingBlock;
import com.ibm.zurich.idmx.buildingBlock.rangeProof.RangeProofBuildingBlock;
import com.ibm.zurich.idmx.buildingBlock.rangeProof.fourSq.FourSquaresRangeProofBuildingBlock;
import com.ibm.zurich.idmx.buildingBlock.signature.SignatureBuildingBlock;
import com.ibm.zurich.idmx.buildingBlock.signature.cl.ClSignatureBuildingBlock;
import com.ibm.zurich.idmx.buildingBlock.structural.reveal.RevealAttributeBuildingBlock;
import com.ibm.zurich.idmx.buildingBlock.systemParameters.EcryptSystemParametersWrapper;
import com.ibm.zurich.idmx.exception.ConfigurationException;
import com.ibm.zurich.idmx.exception.ProofException;
import com.ibm.zurich.idmx.exception.SerializationException;
import com.ibm.zurich.idmx.guice.CryptoTestModule;
import com.ibm.zurich.idmx.interfaces.proofEngine.ZkDirector;
import com.ibm.zurich.idmx.interfaces.signature.ListOfSignaturesAndAttributes;
import com.ibm.zurich.idmx.interfaces.state.CarryOverStateIssuer;
import com.ibm.zurich.idmx.interfaces.state.CarryOverStateRecipient;
import com.ibm.zurich.idmx.interfaces.state.IssuanceStateRecipient;
import com.ibm.zurich.idmx.interfaces.util.BigInt;
import com.ibm.zurich.idmx.interfaces.util.BigIntFactory;
import com.ibm.zurich.idmx.interfaces.util.RandomGeneration;
import com.ibm.zurich.idmx.interfaces.zkModule.ZkModuleProver;
import com.ibm.zurich.idmx.interfaces.zkModule.ZkModuleProverIssuance;
import com.ibm.zurich.idmx.interfaces.zkModule.ZkModuleVerifier;
import com.ibm.zurich.idmx.interfaces.zkModule.ZkModuleVerifierIssuance;
import com.ibm.zurich.idmx.jaxb.wrapper.CredentialSpecificationWrapper;
import eu.abc4trust.keyManager.KeyManager;
import eu.abc4trust.xml.*;
import utils.IdemixUtils;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.util.*;

public class BenchmarkIdemix {

    private static final int numberOfTests=2;
    private static final String SYSTEM_PARAM_FILE= "system_params_2048.xml";
    private static final String VERIFIER_PARAM_FILE= "verifier_params.xml";
    private static final String ISSUER_PARAM_FILE1= "issuer_params.xml";
    private static final String ISSUER_PARAM_FILE2= "issuer_params2.xml";
    private static final String KEY_PAIR_FILE_PREFIX="issuerKeyPair_";
    private static final String CRED_SPEC_FILE_PREFIX="credentialSpecification";
    private static final String USERNAME="BenchUser";
    private static final String IDENTIFIER_OF_ZK_MODULE ="bench";
    private static int warmup=1;
    private static int minNumberOfAttributes=4;
    private static int maxNumberOfAttributes=4;


    public static void main(String[] args) throws Exception{
        if(args.length==2){
            minNumberOfAttributes=Integer.valueOf(args[0]);
            maxNumberOfAttributes=Integer.valueOf(args[1]);
        }
        System.out.println("Starting benchmark Idemix issuance");
        File outputFileIssuance=new File("BenchIdemixIssuance.txt");
        PrintWriter writerIssuance=new PrintWriter(outputFileIssuance);
        for(int i=minNumberOfAttributes; i<=maxNumberOfAttributes ; i++) {
            List<Object> times= benchIssuanceAndProof(i);
            writeTest(writerIssuance,i,(List<Long>)times.get(0),"NoAttr");
            writeWholeFile(i,(Map<Integer,List<Long>>)times.get(1),"ZkProof");
            writeWholeFile(i,(Map<Integer,List<Long>>)times.get(2),"ZkVerify");
        }
        writerIssuance.close();
        System.out.println("Benchmark Idemix issuance finished");

    }

    private static List<Object> benchIssuanceAndProof(int nAttr) throws Exception {
        Injector injector = Guice.createInjector(new CryptoTestModule());
        final KeyManager keyManager = injector.getInstance(KeyManager.class);
        IssuerParameters ip = IdemixUtils.getResource(ISSUER_PARAM_FILE1, IssuerParameters.class, true);


        // We can load more than ONE parameters. During the verification, we're going to query all of them until one is valid.
        // If none of them is valid then the verification will fail.

        IssuerParameters ip2 = IdemixUtils.getResource(ISSUER_PARAM_FILE2, IssuerParameters.class, true);
        keyManager.storeIssuerParameters(ip.getParametersUID(),ip);
        keyManager.storeIssuerParameters(ip2.getParametersUID(),ip2);


        List<Long> issuanceTimes=new LinkedList<>();
        Map<Integer,List<Long>> zkProofTimes=new HashMap<>();
        for(int i=0;i<=nAttr;i++)
            zkProofTimes.put(i,new LinkedList<>());
        Map<Integer,List<Long>> zkVerifyTimes=new HashMap<>();
        for(int i=0;i<=nAttr;i++)
            zkVerifyTimes.put(i,new LinkedList<>());
        //Load System Parameters and key pair, setUp building block,director,factories... using injector
        SystemParameters systemParameters = IdemixUtils.getResource(SYSTEM_PARAM_FILE, SystemParameters.class, true);
        EcryptSystemParametersWrapper spWrapper = new EcryptSystemParametersWrapper(systemParameters);
        KeyPair keyPair = IdemixUtils.getResource(KEY_PAIR_FILE_PREFIX+nAttr+".xml", KeyPair.class,  true);
        SignatureBuildingBlock sigBB = injector.getInstance(ClSignatureBuildingBlock.class);

        BigIntFactory bigIntFactory = injector.getInstance(BigIntFactory.class);
        ZkDirector director = injector.getInstance(ZkDirector.class);
        RandomGeneration randomGeneration = injector.getInstance(RandomGeneration.class);
        CredentialSpecification credentialSpecification = IdemixUtils.getResource(CRED_SPEC_FILE_PREFIX+nAttr+".xml", CredentialSpecification.class, true);
        RevealAttributeBuildingBlock revealBB = injector.getInstance(RevealAttributeBuildingBlock.class);
        CredentialSpecificationWrapper credSpecWrapper =new CredentialSpecificationWrapper(credentialSpecification, bigIntFactory);
        BigInt credSpecId =credSpecWrapper.getCredSpecId(spWrapper.getHashFunction());
        long start1,finish1,start2,finish2;
        for(int i=0;i<warmup+numberOfTests;i++) {
            //Random attribute values
            List<BigInt> attributes = new ArrayList<BigInt>();
            BigInt a=randomGeneration.generateRandomNumber(spWrapper.getAttributeLength());
            for (int j=0;j<nAttr;j++) {
                attributes.add(a);
                a=a.add(a);
            }
            int numberOfAttributes = attributes.size();
            //Sin CarryOver porque es lo equivalente a PS (donde todos los atributos pasan por Issuer y no los commitments)
            CarryOverStateIssuer coiss = null;
            CarryOverStateRecipient corec = null;
            //Issuance of credential
            start1=System.nanoTime();
            ZkModuleProverIssuance zkp =
                    sigBB.getZkModuleProverIssuance(systemParameters, null, keyPair.getPublicKey(),
                            keyPair.getPrivateKey(), "bench", credSpecId, false, attributes, coiss);
            ZkProof proof = director.buildProof(USERNAME, Collections.singletonList(zkp), systemParameters);
            finish1=System.nanoTime();
            //Verify validity of and ZK proof of honest issuance
            start2=System.nanoTime();
            ZkModuleVerifierIssuance zkv =
                    sigBB.getZkModuleVerifierIssuance(systemParameters, null, keyPair.getPublicKey(),
                            "bench", credSpecId, false, numberOfAttributes, corec);
            boolean ok = director.verifyProof(proof, Collections.singletonList(zkv), systemParameters);
            finish2=System.nanoTime();
            if(i>=warmup)
                issuanceTimes.add(finish2+finish1-start2-start1);
            System.out.println(ok);
            IssuanceStateRecipient stateRecipient = zkv.recoverIssuanceState();
            ListOfSignaturesAndAttributes sig = sigBB.extractSignature(null, stateRecipient);
            for(int j=0;j<=0;j++){ //XXX Only hide attributes
                List<Long> zkTimes=benchZK(j,sig,keyPair.getPublicKey(),credSpecId,systemParameters,sigBB,revealBB,director,injector);
                if(i>=warmup){
                    zkProofTimes.get(j).add(zkTimes.get(0));
                    zkVerifyTimes.get(j).add(zkTimes.get(1));
                }
            }
        }
        List<Object> times=new LinkedList<>();
        times.add(issuanceTimes);
        times.add(zkProofTimes);
        times.add(zkVerifyTimes);
        return times;
    }

    private static List<Long> benchZK(int numberOfRevealedAttr,ListOfSignaturesAndAttributes sigAndAttr,PublicKey pk,BigInt credSpecId, SystemParameters systemParameters, SignatureBuildingBlock clSignatureBuildingBlock, RevealAttributeBuildingBlock revealBB, ZkDirector zkDirector, Injector injector) throws ProofException, ConfigurationException, URISyntaxException, SerializationException {
        VerifierParameters verifierParameters = IdemixUtils.getResource(VERIFIER_PARAM_FILE, VerifierParameters.class, true);

        RangeProofBuildingBlock rangeBB=injector.getInstance(FourSquaresRangeProofBuildingBlock.class);
        PseudonymBuildingBlock pseudoBB=injector.getInstance(StandardPseudonymBuildingBlock.class);
        URI deviceUri=null;///new URI("urn:device");
        URI scope=new URI("urn:scope");
        systemParameters.getCryptoParams();
        //AbstractPseudonym pseudonym=pseudoBB.createPseudonym(systemParameters,null,deviceUri,USERNAME,scope);
    //Always use last attribute for range/pseudonym proof
        List<Long> times=new LinkedList<>();
        List<Integer> revealed=new LinkedList<>();
        for(int i=0;i<numberOfRevealedAttr;i++){
            revealed.add(i);
        }
        Signature sig = sigAndAttr.signature;
        SignatureToken tok = sig.getSignatureToken().get(0);
        List<BigInt> attributes = sigAndAttr.attributes;
        int numberOfAttributes = attributes.size();


        URI credentialUri = null;

        List<ZkModuleProver> modulesProver = new ArrayList<ZkModuleProver>();
        List<ZkModuleVerifier> modulesVerifier = new ArrayList<ZkModuleVerifier>();

        long start=System.nanoTime();
        for (int i : revealed) {
            ZkModuleProver zk = revealBB.getZkModuleProver(IDENTIFIER_OF_ZK_MODULE + ":" + i);
            modulesProver.add(zk);
        }
        ZkModuleProver zkp =
                clSignatureBuildingBlock.getZkModuleProverPresentation(systemParameters, null, pk,
                        IDENTIFIER_OF_ZK_MODULE, tok, attributes, credSpecId, deviceUri, USERNAME, credentialUri);
        modulesProver.add(zkp);

        //ZkModuleProver zkpseudo=pseudoBB.getZkModuleProver(systemParameters, null,IDENTIFIER_OF_ZK_MODULE,pseudonym,deviceUri,USERNAME,scope);
        //modulesProver.add(zkpseudo); //XXX Added

        System.out.println("size:"+attributes.size());
        System.out.println("0:"+attributes.get(0).toString());
        System.out.println("1:"+attributes.get(1).toString());
        String lhs=IDENTIFIER_OF_ZK_MODULE + ":" + "1";
        String rhs=IDENTIFIER_OF_ZK_MODULE + ":" + "0";

        ZkModuleProver zkrange=rangeBB.getZkModuleProver(systemParameters,verifierParameters,lhs,rhs,false,0);
        modulesProver.add(zkrange);

        ZkProof proof = zkDirector.buildProof(USERNAME, modulesProver, systemParameters);
        long finish=System.nanoTime();
        times.add(finish-start);

        start=System.nanoTime();
        for (int i : revealed) {
            ZkModuleVerifier zk = revealBB.getZkModuleVerifier(IDENTIFIER_OF_ZK_MODULE + ":" + i, attributes.get(i));
            modulesVerifier.add(zk);
        }
        ZkModuleVerifier zkv =
                clSignatureBuildingBlock.getZkModuleVerifierPresentation(systemParameters, null, pk,
                        IDENTIFIER_OF_ZK_MODULE, credSpecId, numberOfAttributes, false);
        modulesVerifier.add(zkv);

       // ZkModuleVerifier zkpseudoverf=pseudoBB.getZkModuleVerifier(systemParameters,null,IDENTIFIER_OF_ZK_MODULE,scope,pseudoBB.getPseudonymAsBytes(pseudonym));
        //modulesVerifier.add(zkpseudoverf);

        ZkModuleVerifier zkrangeverf= rangeBB.getZkModuleVerifier(systemParameters,verifierParameters,lhs,rhs,false,0);
        modulesVerifier.add(zkrangeverf);

        boolean result = zkDirector.verifyProof(proof, modulesVerifier, systemParameters);
        finish=System.nanoTime();
        times.add(finish-start);
        System.out.println(result+" nRevAttr "+numberOfRevealedAttr);
        return times;
    }

    private static void writeTest(PrintWriter writer,int nAttr, List<Long> times,String param) {
        String output=param+"-"+String.format("%02d",nAttr);
        for(long t:times){
            output+=" "+((double)t/(double)BenchmarkSigning.factorToMilliseconds);
        }
        writer.println(output);
    }


    private static void writeWholeFile(int nAttr, Map<Integer, List<Long>> times, String name) throws FileNotFoundException {
        File outputFile=new File("BenchIdemix"+name+"_NAttr-"+String.format("%02d",nAttr)+".txt");
        PrintWriter writer=new PrintWriter(outputFile);
        for(int i=0;i<=nAttr;i++)
            writeTest(writer,i,times.get(i),"NoRevAttr");
        writer.close();
    }
}

