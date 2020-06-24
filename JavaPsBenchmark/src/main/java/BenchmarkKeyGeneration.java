import multisign.MS;
import multisign.MSauxArg;
import multisign.MSprivateKey;
import multisign.MSverfKey;
import pairingInterfaces.PairingBuilder;
import psmultisign.PSauxArg;
import psmultisign.PSms;
import utils.Pair;

import java.io.File;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class BenchmarkKeyGeneration {

    private static final int numberOfTests=50;
    private static int minNumberOfAttributes=1;
    private static int maxNumberOfAttributes=4;
    private static int numberOfSigners=2;
    private static int warmup=50;

    //Usage: two arguments, first is the minimum number of attributes and second the maximum, or no arguments for default values.
    public static void main(String[] args) throws Exception{
        if(args.length==1)
            numberOfSigners =Integer.valueOf(args[0]);
        if(args.length==3){
            numberOfSigners =Integer.valueOf(args[0]);
            minNumberOfAttributes=Integer.valueOf(args[1]);
            maxNumberOfAttributes=Integer.valueOf(args[2]);
        }
        System.out.println("Starting benchmark key generation");
        File outputFile=new File("BenchKeyGen"+ BenchmarkSigning.pairingName+".txt");
        PrintWriter writer=new PrintWriter(outputFile);
        File outputFileKeyAggr=new File("BenchKeyAggr"+BenchmarkSigning.pairingName+"_NS-"+String.format("%02d",numberOfSigners)+".txt");
        PrintWriter writerKeyAggr=new PrintWriter(outputFileKeyAggr);
        for(int i=minNumberOfAttributes; i<=maxNumberOfAttributes ; i++) {
            List<List<Long>> times=benchKeyGen(i);
            warmup=3; //For first bench need high warmup value
            writeTest(writer,i,times.get(0));
            writeTest(writerKeyAggr,i,times.get(1));
        }
        writer.close();
        writerKeyAggr.close();
        System.out.println("Benchmark key generation finished");
    }

    private static void writeTest(PrintWriter writer,int nAttr, List<Long> times) {
        String output="NoAttr-"+String.format("%02d",nAttr);
        for(long t:times){
            output+=" "+((double)t/(double)BenchmarkSigning.factorToMilliseconds);
        }
        writer.println(output);
    }

    private static List<List<Long>> benchKeyGen(int numberOfAttributes) throws Exception {
        List<List<Long>> times=new LinkedList<>();
        List<Long> timesKg=new LinkedList<>();
        List<Long> timesKeyAggr=new LinkedList<>();
        Set<String> attrNames=new HashSet<>();
        for(int i=0;i<numberOfAttributes;i++)
            attrNames.add(""+i);
        MSauxArg auxArg=new PSauxArg(BenchmarkSigning.pairingBuilderName,attrNames);
        MS signingScheme=new PSms();
        signingScheme.setup(numberOfSigners,auxArg);
        long start,finish;
        MSverfKey[] serverVK=new MSverfKey[numberOfSigners];
        /*
        if(i>=warmup)
            keyAggrTimes.add(finish-start);*/
        for(int i=0;i<numberOfTests+warmup;i++){
            for(int j=0;j<numberOfSigners;j++){
                start=System.nanoTime();
                Pair<MSprivateKey,MSverfKey> keys=signingScheme.kg();
                finish=System.nanoTime();
                if(j==0 && i>=warmup)
                    timesKg.add(finish-start);
                serverVK[j]=keys.getSecond();
            }
            start=System.nanoTime();
            signingScheme.kAggr(serverVK);
            finish=System.nanoTime();
            if(i>=warmup)
                timesKeyAggr.add(finish-start);
        }
        times.add(timesKg);
        times.add(timesKeyAggr);
        return times;
    }
}
