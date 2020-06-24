import multisign.*;
import pairingInterfaces.PairingBuilder;
import pairingInterfaces.ZpElement;
import psmultisign.*;
import utils.Pair;
import java.io.File;
import java.io.PrintWriter;
import java.util.*;

public class BenchmarkSigning {

    public static final String pairingName="BLS461";
    public static final String pairingBuilderName="pairing"+pairingName+".PairingBuilder"+pairingName;
    public static final int factorToMilliseconds=1000000;
    private static final int numberOfTests=50;
    private static int numberOfSigners =3;
    private static int minNumberOfAttributes=1;
    private static int maxNumberOfAttributes=4;
    private static int warmup=50;

    //Usages: Without arguments default values for numberOfServers and min/max of attributes
    // With 3 arguments specify: 1- number of severs, 2-minimum number of attr, 3-maximum number of attr
    public static void main(String[] args) throws Exception{
        if(args.length==1)
            numberOfSigners =Integer.valueOf(args[0]);
        if(args.length==3){
            numberOfSigners =Integer.valueOf(args[0]);
            minNumberOfAttributes=Integer.valueOf(args[1]);
            maxNumberOfAttributes=Integer.valueOf(args[2]);
        }
        System.out.println("Starting benchmark sign-comb-verf");
        File outputFileSign=new File("BenchSign"+pairingName+"_NS-"+String.format("%02d",numberOfSigners)+".txt");
        PrintWriter writerSign=new PrintWriter(outputFileSign);
        File outputFileCombine=new File("BenchCombine"+pairingName+"_NS-"+String.format("%02d",numberOfSigners)+".txt");
        PrintWriter writerCombine=new PrintWriter(outputFileCombine);
        File outputFileVerify=new File("BenchVerify"+pairingName+"_NS-"+String.format("%02d",numberOfSigners)+".txt");
        PrintWriter writerVerify=new PrintWriter(outputFileVerify);
        for(int i=minNumberOfAttributes; i<=maxNumberOfAttributes ; i++) {
            List<List<Long>> times=benchSigning(i);
            warmup=3; //For first bench need high warmup value
            writeTest(writerSign,i,times.get(0));
            writeTest(writerCombine,i,times.get(1));
            writeTest(writerVerify,i,times.get(2));
        }
        writerSign.close();
        writerCombine.close();
        writerVerify.close();
        System.out.println("Benchmark sign-comb-verf finished");
    }

    private static void writeTest(PrintWriter writer,int nAttr, List<Long> times) {
        String output="NoAttr-"+String.format("%02d",nAttr);
        for(long t:times){
            output+=" "+((double)t/(double)factorToMilliseconds);
        }
        writer.println(output);
    }

    private static List<List<Long>> benchSigning(int numberOfAttributes) throws Exception{
        List<Long> signingTimes=new LinkedList<>();
        List<Long> combiningTimes=new LinkedList<>();
        List<Long> verifyingTimes=new LinkedList<>();
        List<Long> keyAggrTimes=new LinkedList<>();
        Set<String> attrNames=new HashSet<>();
        long start,finish;
        for(int i=0;i<numberOfAttributes;i++)
            attrNames.add(""+i);
        MSauxArg auxArg=new PSauxArg(pairingBuilderName,attrNames);
        MS signingScheme=new PSms();
        signingScheme.setup(numberOfSigners,auxArg);
        MSprivateKey[] serverSK=new MSprivateKey[numberOfSigners];
        MSverfKey[] serverVK=new MSverfKey[numberOfSigners];
        PairingBuilder builder=(PairingBuilder) Class.forName(pairingBuilderName).newInstance();
        for(int j=0;j<numberOfSigners;j++){
            Pair<MSprivateKey,MSverfKey> keys=signingScheme.kg();
            serverSK[j]=keys.getFirst();
            serverVK[j]=keys.getSecond();
        }
        start=System.nanoTime();
        MSverfKey aggregatedKey=signingScheme.kAggr(serverVK);
        finish=System.nanoTime();
        /*
        if(i>=warmup)
            keyAggrTimes.add(finish-start);*/

        for(int i=0;i<numberOfTests+warmup;i++){

            Map<String, ZpElement> attributes=new HashMap<>();
            for(String attr:attrNames){
                attributes.put(attr,builder.getRandomZpElement());
            }
            ZpElement epoch=builder.getRandomZpElement();
            MSmessage messageToSign=new PSmessage(attributes,epoch);
            MSsignature[] shares=new MSsignature[numberOfSigners];
            for(int j=0;j<numberOfSigners;j++){
                start=System.nanoTime();
                MSsignature signature=signingScheme.sign(serverSK[j],messageToSign);
                finish=System.nanoTime();
                shares[j]=signature;
                if(j==1 && i>=warmup)
                    signingTimes.add(finish-start);
            }
            start=System.nanoTime();
            MSsignature completeSignature=signingScheme.comb(serverVK,shares);
            finish=System.nanoTime();
            if(i>=warmup)
                combiningTimes.add(finish-start);
            start=System.nanoTime();
            signingScheme.verf(aggregatedKey,messageToSign,completeSignature);
            finish=System.nanoTime();
            if(i>=warmup)
                verifyingTimes.add(finish-start);
        }
        List<List<Long>> times=new LinkedList<>();
        times.add(signingTimes);
        times.add(combiningTimes);
        times.add(verifyingTimes);
        times.add(keyAggrTimes);
        return times;
    }
}
