package psmultisign;

import pairingInterfaces.*;
import utils.Pair;
import exceptions.*;
import multisign.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * PS signatures as an implementation of a multi-signature scheme. It relies on generic Pairing, group and hash interfaces that must
 * be then instantiated using specific cryptographic tools.
 */
public class PSms implements MS {

    private Pairing pairing;
    private PairingBuilder builder;
    private int n;
    private Set<String> attributeNames;
    private Group1Element g1;
    private Group2Element g2;
    private Hash0 h0;
    private Hash1 h1;
    private Hash2 h2;

    @Override
    public MSpublicParam setup(int n, MSauxArg aux) throws MSSetupException {
        //Check validity of arguments
        if(pairing !=null)
            throw new IllegalStateException("Only run setup once.");
        if(!(aux instanceof PSauxArg))
            throw new IllegalArgumentException("Aux argument must be a PSauxArg object");
        //Casting to PS types
        PSauxArg auxArg=(PSauxArg) aux;
        //Getting a pairing through introspection
        try {
            builder=(PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
        } catch (Exception e) {
            throw new MSSetupException("Could not create builder from name " + auxArg.getPairingName());
        }
        //Obtain parameters from arguments while checking validity of values
        this.n=n;
        this.attributeNames=auxArg.getAttributeNames();
        if(n<=0 || attributeNames==null || attributeNames.size()==0)
            throw new MSSetupException("Invalid arguments for setup");
        //Get generators for groups 1 and 2 and the specific hashing algorithms.
        pairing =builder.getPairing();
        g1=builder.getGroup1Generator();
        g2=builder.getGroup2Generator();
        h0=builder.getHash0();
        h1=builder.getHash1();
        h2=builder.getHash2();
        return new PSpublicParam(n,auxArg);
    }

    @Override
    public Pair<MSprivateKey, MSverfKey> kg() {
        //Check if properly setup
        if(pairing==null)
            throw new IllegalStateException("It is necessary to first setup the signature scheme.");
        //Generate random Zp elements for the secret key sk.
        ZpElement x=builder.getRandomZpElement();
        ZpElement y_m=builder.getRandomZpElement();
        ZpElement y_epoch=builder.getRandomZpElement();
        Map<String,ZpElement> y=new HashMap<>();
        for(String attr:attributeNames)
            y.put(attr,builder.getRandomZpElement());
        PSprivateKey sk=new PSprivateKey(x,y_m,y,y_epoch);
        //Generate the corresponding verification key through exponentiation of G2 generator by the sk members.
        Group2Element vx=g2.exp(x);
        Group2Element vy_m=g2.exp(y_m);
        Group2Element vy_epoch=g2.exp(y_epoch);
        Map<String,Group2Element> vy=new HashMap<>();
        for(String attr:attributeNames)
            vy.put(attr,g2.exp(y.get(attr)));
        PSverfKey vk=new PSverfKey(vx,vy_m,vy,vy_epoch);
        return new Pair<>(sk,vk);
    }

    @Override
    public PSverfKey kAggr(MSverfKey[] vks) {
        //Check if properly setup and validity of arguments
        if(pairing==null)
            throw new IllegalStateException("It is necessary to first setup the signature scheme.");
        if(n!=vks.length)
            throw new IllegalArgumentException("Wrong number of verification keys.");
        //Casting to PS types
        PSverfKey[] vksPS=new PSverfKey[vks.length];
        for(int i=0;i<vks.length;i++){
            if(!(vks[i] instanceof PSverfKey))
                throw new IllegalArgumentException("Verification keys must correspond to a PS signature scheme.");
            vksPS[i]=(PSverfKey) vks[i];
        }
        //Generate t<-H1(Verification keys)
        ZpElement[] t=h1.hash(vksPS);
        // Multiplication+exponentiation of member X of the verification keys (Getting X member of Avk).
        Group2Element ax=vksPS[0].getVX().exp(t[0]);
        for(int i=1;i<vksPS.length;i++)
            ax=ax.mul(vksPS[i].getVX().exp(t[i]));
        // Multiplication+exponentiation of member Y_m' of the verification keys (Getting Y_m' member of Avk).
        Group2Element ay_m=vksPS[0].getVY_m().exp(t[0]);
        for(int i=1;i<vksPS.length;i++)
            ay_m=ay_m.mul(vksPS[i].getVY_m().exp(t[i]));
        // Multiplication+exponentiation of member Y_epoch of the verification keys (Getting Y_epoch member of Avk).
        Group2Element ay_epoch=vksPS[0].getVY_epoch().exp(t[0]);
        for(int i=1;i<vksPS.length;i++)
            ay_epoch=ay_epoch.mul(vksPS[i].getVY_epoch().exp(t[i]));
        // Multiplication+exponentiation of members Y_i of the verification keys (Getting Y_i members of Avk).
        Map<String,Group2Element> ay=new HashMap<>();
        for(String attr:attributeNames){
            Group2Element aux=vksPS[0].getVY().get(attr);
            if(aux==null)       //Check that the verification keys has a member for every attribute of the signature scheme.
                throw new IllegalArgumentException("Invalid verification key for this instance of PS-MS scheme.");
            Group2Element yattr=aux.exp(t[0]);
            for (int i=1;i<vksPS.length;i++){
                aux= vksPS[i].getVY().get(attr);
                if(aux==null)       //Check that the verification keys has a member for every attribute of the signature scheme.
                    throw new IllegalArgumentException("Invalid message for this instance of PS-MS scheme.");
                yattr=yattr.mul(aux.exp(t[i]));
            }
            ay.put(attr,yattr);
        }
        return new PSverfKey(ax,ay_m,ay,ay_epoch);
    }

    @Override
    public PSsignature sign(MSprivateKey sk, MSmessage m) {
        //Check if properly setup and validity of arguments
        if(pairing==null)
            throw new IllegalStateException("It is necessary to first setup the signature scheme.");
        if(!(sk instanceof PSprivateKey) || !(m instanceof PSmessage))
            throw new IllegalArgumentException("Arguments must correspond to PS objects.");
        if(((PSprivateKey) sk).getY().size()!=attributeNames.size())
            throw new IllegalArgumentException("Invalid private key for this PS-MS scheme");
        if(((PSmessage) m).getM().size()!=attributeNames.size())
            throw new IllegalArgumentException("Invalid message for this PS-MS scheme");
        //Casting to PS types
        PSprivateKey skPS=(PSprivateKey) sk;
        PSmessage mPS=(PSmessage) m;
        //Obtain (m',h) <- H0(m)
        Collection<ZpElement> valuesToSign=new LinkedList<>(mPS.getM().values());
        valuesToSign.add(mPS.getEpoch());
        Pair<ZpElement,Group1Element> mh=h0.hash(valuesToSign);
        ZpElement mPrim=mh.getFirst();
        Group1Element h=mh.getSecond();
        //Generate exponent of third member of the signature sigma2.
        ZpElement exponent=skPS.getX();
        exponent=exponent.add(mPrim.mul(skPS.getY_m()));
        exponent=exponent.add(mPS.getEpoch().mul(skPS.getY_epoch()));
        for(String attr:attributeNames){
            ZpElement aux=skPS.getY().get(attr);
            if(aux==null)
                throw new IllegalArgumentException("Invalid private key for this instance of PS-MS scheme.");
            ZpElement auxM=mPS.getM().get(attr);
            if(auxM==null)
                throw new IllegalArgumentException("Invalid message for this instance of PS-MS scheme.");
            exponent=exponent.add(aux.mul(auxM));
        }
        //Generate signature
        return new PSsignature(mPrim,h,h.exp(exponent));
    }

    @Override
    public PSsignature comb(MSverfKey[] vks, MSsignature[] signs) {
        //Check if properly setup and validity of arguments
        if(pairing==null)
            throw new IllegalStateException("It is necessary to first setup the signature scheme.");
        if(n!=vks.length)
            throw new IllegalArgumentException("Wrong number of verification keys.");
        if(n!=signs.length)
            throw new IllegalArgumentException("Wrong number of signature shares.");
        //Casting to PS types
        PSverfKey[] vksPS=new PSverfKey[vks.length];
        for(int i=0;i<vks.length;i++){
            if(!(vks[i] instanceof PSverfKey))
                throw new IllegalArgumentException("Verification keys must correspond to a PS signature scheme.");
            vksPS[i]=(PSverfKey) vks[i];
        }
        PSsignature[] signsPS=new PSsignature[signs.length];
        for(int i=0;i<signs.length;i++){
            if(!(signs[i] instanceof PSsignature))
                throw new IllegalArgumentException("Signature shares must correspond to a PS signature scheme.");
            signsPS[i]=(PSsignature) signs[i];
        }
        //Get t<-H1(Verification keys)
        ZpElement[] t=h1.hash(vksPS);
        //Multiplication+exponentiation of sigma 2 of the signature shares.
        ZpElement mPrim=signsPS[0].getMPrim();
        Group1Element sigma1=signsPS[0].getSigma1();
        Group1Element sigma2=signsPS[0].getSigma2().exp(t[0]);
        for(int i=1;i<signs.length;i++){
            if(!mPrim.equals(signsPS[i].getMPrim()) || !sigma1.equals(signsPS[i].getSigma1())) //Check m' and sigma1 are equal for every share
                throw new IllegalArgumentException("Signature shares are not compatible.");
            sigma2=sigma2.mul(signsPS[i].getSigma2().exp(t[i]));
        }
        return new PSsignature(mPrim,sigma1,sigma2);
    }

    @Override
    public boolean verf(MSverfKey avk, MSmessage m, MSsignature sign) {
        //Check if properly setup and validity of arguments
        if(pairing==null)
            throw new IllegalStateException("It is necessary to first setup the signature scheme.");
        if(!(avk instanceof PSverfKey))
            throw new IllegalArgumentException("Verification key must correspond to a PS signature scheme.");
        if(!(m instanceof PSmessage))
            throw new IllegalArgumentException("Message must correspond to a PS signature scheme.");
        if(!(sign instanceof PSsignature))
            throw new IllegalArgumentException("Signature must correspond to a PS signature scheme.");
        if(((PSverfKey) avk).getVY().size()!=attributeNames.size())
            throw new IllegalArgumentException("Invalid verification key for this PS-MS scheme");
        if(((PSmessage) m).getM().size()!=attributeNames.size())
            throw new IllegalArgumentException("Invalid message for this PS-MS scheme");
        //Casting to PS types
        PSverfKey avkPS=(PSverfKey)avk;
        PSmessage mPS=(PSmessage) m;
        PSsignature signPS=(PSsignature)sign;
        //Check sigma1!=1G
        if(signPS.getSigma1().isUnity())
            return false;
        //Obtain X * (Y_m')^m'* Prod (Y_i)^m_i
        Group2Element el2=avkPS.getVX();
        el2=el2.mul(avkPS.getVY_m().exp(signPS.getMPrim()));
        el2=el2.mul(avkPS.getVY_epoch().exp(mPS.getEpoch()));
        for(String attr:attributeNames){
            Group2Element aux=avkPS.getVY().get(attr);
            if(aux==null)
                throw new IllegalArgumentException("Invalid verification key for this instance of PS-MS scheme.");
            ZpElement auxM=mPS.getM().get(attr);
            if(auxM==null)
                throw new IllegalArgumentException("Invalid message for this instance of PS-MS scheme.");
            el2=el2.mul(aux.exp(auxM));
        }
        //Check pairing condition e(sigma1, X * (Y_m')^m'* Prod (Y_i)^m_i )=e(sigma2,group2generator)
        return pairing.pair(signPS.getSigma1(),el2).equals(pairing.pair(signPS.getSigma2(),g2));
    }

    @Override
    public PSzkToken presentZKtoken(MSverfKey avk, Set<String> revealedAttributes, MSmessage attributes, String m, MSsignature sign) {
        //Check if properly setup and validity of arguments
        if(pairing==null)
            throw new IllegalStateException("It is necessary to first setup the signature scheme.");
        if(!(avk instanceof PSverfKey))
            throw new IllegalArgumentException("Verification key must correspond to a PS signature scheme.");
        if(!(attributes instanceof PSmessage))
            throw new IllegalArgumentException("Message must correspond to a PS signature scheme.");
        if(!(sign instanceof PSsignature))
            throw new IllegalArgumentException("Signature must correspond to a PS signature scheme.");
        if(((PSverfKey) avk).getVY().size()!=attributeNames.size())
            throw new IllegalArgumentException("Invalid verification key for this PS-MS scheme");
        if(((PSmessage) attributes).getM().size()!=attributeNames.size())
            throw new IllegalArgumentException("Invalid attributes for this PS-MS scheme");
        if(!attributeNames.containsAll(revealedAttributes))
            throw new IllegalArgumentException("Invalid revealed attributes for this PS-MS scheme");
        //Casting to PS types and computing hidden attributes
        PSverfKey avkPS=(PSverfKey)avk;
        PSmessage attributesPS=(PSmessage) attributes;
        PSsignature signPS=(PSsignature)sign;
        Set<String> hiddenAttributes=attributeNames.stream().filter(attr->!revealedAttributes.contains(attr)).collect(Collectors.toSet());
        //Generate random Zp elements and sigma1', sigma2'
        ZpElement t=builder.getRandomZpElement();
        ZpElement r=builder.getRandomZpElement();
        Group1Element sigma1Prim=signPS.getSigma1().exp(r); //sigma1^r
        Group1Element sigma2Prim=signPS.getSigma2().mul(signPS.getSigma1().exp(t)).exp(r); //(sigma2*sigma1^t)^r
        //Generate random exponents for t, a' and hidden attributes
        ZpElement ranT=builder.getRandomZpElement();
        ZpElement ranAprim=builder.getRandomZpElement();
        Map<String,ZpElement> ranAj=new HashMap<>();
        for(String aj:hiddenAttributes)
            ranAj.put(aj,builder.getRandomZpElement());
        //Calculate c
        /*//One multipairing
        Collection<Pair<Group1Element,Group2Element>> elements=new LinkedList<>();
        elements.add(new Pair<>(sigma1Prim.exp(ranT),g2));
        elements.add(new Pair<>(sigma1Prim.exp(ranAprim),avkPS.getVY_m()));
        for (String aj:hiddenAttributes){
            Group2Element yaj= avkPS.getVY().get(aj);
            if (yaj==null)
                throw new IllegalArgumentException("Invalid verification key for this PS-MS scheme");
            elements.add(new Pair<>(sigma1Prim.exp(ranAj.get(aj)),yaj));
        }
        Group3Element aux= pairing.multiPair(elements);
        ZpElement c=h2.hash(m,avkPS,sigma1Prim,sigma2Prim,aux);*/
        //Single Pairing
        Group2Element aux=g2.exp(ranT);
        aux=aux.mul(avkPS.getVY_m().exp(ranAprim));
        for (String aj:hiddenAttributes){
            Group2Element yaj= avkPS.getVY().get(aj);
            if (yaj==null)
                throw new IllegalArgumentException("Invalid verification key for this PS-MS scheme");
            aux=aux.mul(yaj.exp(ranAj.get(aj)));
        }
        ZpElement c=h2.hash(m,avkPS,sigma1Prim,sigma2Prim,pairing.pair(sigma1Prim,aux));
        //Calculate v_i= ran_i - c * i
        ZpElement vT=ranT.sub(c.mul(t));
        ZpElement vAprim=ranAprim.sub(c.mul(signPS.getMPrim()));
        Map<String,ZpElement> vAj=new HashMap<>();
        for(String hidAttr:hiddenAttributes){
            ZpElement aj= attributesPS.getM().get(hidAttr);
            if (aj==null)
                throw new IllegalArgumentException("Invalid attributes for this PS-MS scheme");
            vAj.put(hidAttr,ranAj.get(hidAttr).sub(c.mul(aj)));
        }
        //Return computed token
        return new PSzkToken(sigma1Prim,sigma2Prim,c,vAj,vT,vAprim);
    }

    @Override
    public boolean verifyZKtoken(MSzkToken token, MSverfKey avk, String m, MSmessage revealedAttributes) {
        //Check if properly setup and validity of arguments
        if(pairing==null)
            throw new IllegalStateException("It is necessary to first setup the signature scheme.");
        if(!(token instanceof PSzkToken))
            throw new IllegalArgumentException("Token must correspond to a PS signature scheme.");
        if(!attributeNames.containsAll(((PSzkToken) token).getV_aj().keySet()))
            throw new IllegalArgumentException("Invalid token for this signature scheme.");
        if(!(avk instanceof PSverfKey))
            throw new IllegalArgumentException("Verification key must correspond to a PS signature scheme.");
        if(((PSverfKey) avk).getVY().size()!=attributeNames.size())
            throw new IllegalArgumentException("Invalid verification key for this PS-MS scheme");
        if(!(revealedAttributes instanceof PSmessage))
            throw new IllegalArgumentException("Attributes must correspond to a PS signature scheme.");
        Collection<String> revealedAttributesNames=((PSmessage) revealedAttributes).getM().keySet();
        if(!attributeNames.containsAll(revealedAttributesNames))
            throw new IllegalArgumentException("Invalid revealed attributes for this PS-MS scheme");
        //Casting to PS types and computing hidden attributes
        PSverfKey avkPS=(PSverfKey)avk;
        PSmessage revealedAttributesPS=(PSmessage) revealedAttributes;
        PSzkToken tokenPS=(PSzkToken) token;
        Set<String> hiddenAttributes=attributeNames.stream().filter(attr->!revealedAttributesNames.contains(attr)).collect(Collectors.toSet());
        //Check that the hiddenAttributes used to compute the token are the same as the ones computed as
        // the difference between the complete set of attributes and the revealed attributes.
        if(!hiddenAttributes.containsAll(tokenPS.getV_aj().keySet()) || !tokenPS.getV_aj().keySet().containsAll(hiddenAttributes))
            return false;
        //Compute the necessary pairings and their multiplication.
        Group1Element sigma1=tokenPS.getSigma1();
        Group1Element sigma2=tokenPS.getSigma2();
        /*//One multipairing
        Collection<Pair<Group1Element,Group2Element>> elements=new LinkedList<>();
        elements.add(new Pair<>(sigma2.exp(tokenPS.getC()),g2));
        elements.add(new Pair<>(sigma1.exp(tokenPS.getV_t()),g2));
        elements.add(new Pair<>(sigma1.exp(tokenPS.getV_aPrim()),avkPS.getVY_m()));
        elements.add(new Pair<>(sigma1.invExp(tokenPS.getC()),avkPS.getVX()));
        elements.add(new Pair<>(sigma1.invExp(tokenPS.getC().mul(revealedAttributesPS.getEpoch())),avkPS.getVY_epoch()));
        for(String hidAttr:hiddenAttributes){
            Group2Element yHidAttr=avkPS.getVY().get(hidAttr);
            if(yHidAttr==null)
                throw new IllegalArgumentException("Invalid verification key (does not contain base for hidden attribute)"); //dont need to check if Vaj has each member because it was checked before.
            elements.add(new Pair<>(sigma1.exp(tokenPS.getV_aj().get(hidAttr)),yHidAttr));
        }
        for(String revAttr:revealedAttributesNames){
            Group2Element yRevAttr=avkPS.getVY().get(revAttr);
            if(yRevAttr==null)
                throw new IllegalArgumentException("Invalid verification key (does not contain base for revealed attribute)");
            ZpElement auxExp=revealedAttributesPS.getM().get(revAttr).mul(tokenPS.getC());
            elements.add(new Pair<>(sigma1.invExp(auxExp),yRevAttr));
        }
        Group3Element aux= pairing.multiPair(elements);*/
        //Alternative:
        Group2Element auxEl2=g2.exp(tokenPS.getV_t());
        auxEl2=auxEl2.mul(avkPS.getVY_m().exp(tokenPS.getV_aPrim()));
        auxEl2=auxEl2.mul(avkPS.getVX().invExp(tokenPS.getC()));
        auxEl2=auxEl2.mul(avkPS.getVY_epoch().invExp(tokenPS.getC().mul(revealedAttributesPS.getEpoch())));
        for(String hidAttr:hiddenAttributes){
            Group2Element yHidAttr=avkPS.getVY().get(hidAttr);
            if(yHidAttr==null)
                throw new IllegalArgumentException("Invalid verification key, (does not contain base for hidden attribute)"); //we dont need to check if Vaj has each member because it was checked before.
            auxEl2=auxEl2.mul(yHidAttr.exp(tokenPS.getV_aj().get(hidAttr)));
        }
        for(String revAttr:revealedAttributesNames){
            Group2Element yRevAttr=avkPS.getVY().get(revAttr);
            if(yRevAttr==null)
                throw new IllegalArgumentException("Invalid verification key (does not contain base for revealed attribute)");
            ZpElement auxExp=revealedAttributesPS.getM().get(revAttr).mul(tokenPS.getC());
            auxEl2=auxEl2.mul(yRevAttr.invExp(auxExp));
        }
        Collection<Pair<Group1Element,Group2Element>> elements=new LinkedList<>();
        elements.add(new Pair<>(sigma1,auxEl2));
        elements.add(new Pair<>(sigma2.exp(tokenPS.getC()),g2));
        Group3Element aux=pairing.multiPair(elements);
        //Compute hash H2 for the obtained value and compare with c
        ZpElement newC=h2.hash(m,avkPS,sigma1,sigma2,aux);
        return newC.equals(tokenPS.getC());
    }
}