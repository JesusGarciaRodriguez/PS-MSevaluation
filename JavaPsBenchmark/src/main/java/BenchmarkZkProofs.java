import multisign.*;
import pairingInterfaces.PairingBuilder;
import pairingInterfaces.ZpElement;
import psmultisign.*;
import utils.Pair;

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

public class BenchmarkZkProofs {
    private static final int numberOfSigners=2; //This is irrelevant when doing the ZK proof/verification
    private static final int numberOfTests=50;
    private static int numberOfAttributes=3;
    private static int warmup=50;
    //Usages: Without arguments default values for number of attributes
    // With an argument number of attributes
    public static void main(String[] args) throws Exception{
        if(args.length==1)
            numberOfAttributes=Integer.valueOf(args[0]);
        System.out.println("Starting benchmark ZK");
        File outputFileProof=new File("BenchZkProof"+BenchmarkSigning.pairingName+"_NAttr-"+String.format("%02d",numberOfAttributes)+".txt");
        PrintWriter writerProof=new PrintWriter(outputFileProof);
        File outputFileVerify =new File("BenchZkVerify"+BenchmarkSigning.pairingName+"_NAttr-"+String.format("%02d",numberOfAttributes)+".txt");
        PrintWriter writerVerify=new PrintWriter(outputFileVerify);
        for(int i=0;i<=numberOfAttributes; i++){
            List<List<Long>> times=benchZK(i);
            warmup=3; //For first bench need high warmup value
            writeTest(writerProof,i,times.get(0));
            writeTest(writerVerify,i,times.get(1));
        }
        writerProof.close();
        writerVerify.close();
        System.out.println("Benchmark ZK finished");
    }

    private static void writeTest(PrintWriter writer,int nRevealedAttr, List<Long> times) {
        String output="NoRevAttr-"+String.format("%02d",nRevealedAttr);
        for(long t:times){
            output+=" "+((double)t/(double)BenchmarkSigning.factorToMilliseconds);
        }
        writer.println(output);
    }

    private static List<List<Long>> benchZK(int numberOfRevealedAttributes) throws Exception {
        List<Long> proofTimes=new LinkedList<>();
        List<Long> verifyingTimes=new LinkedList<>();
        Set<String> attrNames=new HashSet<>();
        for(int i=0;i<numberOfAttributes;i++)
            attrNames.add(""+i);
        Set<String> revealedAttrNames=new HashSet<>();
        for(int i=0;i<numberOfRevealedAttributes;i++)
            revealedAttrNames.add(""+i);
        MSauxArg auxArg=new PSauxArg(BenchmarkSigning.pairingBuilderName,attrNames);
        MS signingScheme=new PSms();
        signingScheme.setup(numberOfSigners,auxArg);
        MSprivateKey[] serverSK=new MSprivateKey[numberOfSigners];
        MSverfKey[] serverVK=new MSverfKey[numberOfSigners];
        for(int i=0;i<numberOfSigners;i++){
            Pair<MSprivateKey,MSverfKey> keys=signingScheme.kg();
            serverSK[i]=keys.getFirst();
            serverVK[i]=keys.getSecond();
        }
        MSverfKey aggregatedKey=signingScheme.kAggr(serverVK);
        PairingBuilder builder=(PairingBuilder) Class.forName(BenchmarkSigning.pairingBuilderName).newInstance();
        long start,finish;
        Random rand=new Random();
        for(int i=0;i<numberOfTests+warmup;i++) {
            Map<String, ZpElement> attributes = new HashMap<>();
            Map<String,ZpElement> revealedAttributes=new HashMap<>();
            for (String attr : attrNames) {
                attributes.put(attr, builder.getRandomZpElement());
                if(revealedAttrNames.contains(attr))
                    revealedAttributes.put(attr,attributes.get(attr));
            }
            ZpElement epoch = builder.getRandomZpElement();
            MSmessage messageToSign = new PSmessage(attributes, epoch);
            MSmessage messageRevealedAttributes=new PSmessage(revealedAttributes,epoch);
            MSsignature[] shares = new MSsignature[numberOfSigners];
            for (int j = 0; j < numberOfSigners; j++) {
                MSsignature signature = signingScheme.sign(serverSK[j], messageToSign);
                shares[j] = signature;
            }
            MSsignature completeSignature = signingScheme.comb(serverVK, shares);
            String message=""+rand.nextInt();
            start=System.nanoTime();
            MSzkToken token=signingScheme.presentZKtoken(aggregatedKey,revealedAttrNames,messageToSign,message,completeSignature);
            finish=System.nanoTime();
            if(i>=warmup)
                proofTimes.add(finish-start);
            start=System.nanoTime();
            signingScheme.verifyZKtoken(token,aggregatedKey,message,messageRevealedAttributes);
            finish=System.nanoTime();
            if(i>=warmup)
                verifyingTimes.add(finish-start);
        }
        List<List<Long>> times=new LinkedList<>();
        times.add(proofTimes);
        times.add(verifyingTimes);
        return times;
    }
}
