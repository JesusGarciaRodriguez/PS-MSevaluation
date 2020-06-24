package multisign;

import utils.Pair;
import exceptions.MSSetupException;

import java.util.Set;


/**
 * Interface for a multi-signature scheme that can be used to implement pABCs, following deliverable 4.1. Public parameters
 * will be stored so it is not necessary to pass them to all functions.
 */
public interface MS {

    MSpublicParam setup(int n, MSauxArg aux) throws MSSetupException;

    /**
     * Generate a pair of verification-signing keys considering the public parameters.
     * @return Signing key and its correspondent verification key valid for this multi-signature scheme.
     */
    Pair<MSprivateKey, MSverfKey> kg();

    /**
     * Aggregation of the verification keys of the n signers of this scheme.
     * @param vks Collection of the verification keys of the signers.
     * @return Aggregated verification key.
     */
    MSverfKey kAggr(MSverfKey[] vks);

    /**
     * Signing algorithm.
     * @param sk Signing key for the algorithm.
     * @param m Message that will be signed.
     * @return Signature of m using secret key sk and this multi-signature scheme.
     */
    MSsignature sign(MSprivateKey sk, MSmessage m);

    /**
     * Aggregation of every signature share in a single signature.
     * @param vks Verification keys of the signing parties
     * @param signs Signatures of each party.
     * @return Aggregated signature of m using this multi-signature scheme.
     */
    MSsignature comb(MSverfKey[] vks, MSsignature[] signs);


    /**
     * Verification of the validity of a signature with respect to this multi-signature scheme and the verification key avk.
     * @param avk Aggregated verification key.
     * @param m Message m.
     * @param sign Signature we want to verify.
     * @return True if the signature is valid with respect to these parameters, false if it is not.
     */
    boolean verf(MSverfKey avk, MSmessage m, MSsignature sign);

    /**
     * Generation of a token containing a signature of knowledge (ZK proof). If not supported by the specific
     * signing scheme, an UnsupportedOperationException will be thrown.
     * @param avk Aggregated verification key.
     * @param revealedAttributes Names of the attributes that will be revealed.
     * @param attributes List of attributes A.
     * @param m Message that will be signed.
     * @param sign Signature (sign) obtained using MS scheme.
     * @return A presentation token for message m that serves as ZK proof of A and sign.
     */
    MSzkToken presentZKtoken(MSverfKey avk, Set<String> revealedAttributes, MSmessage attributes, String m, MSsignature sign);

    /**
     * Verification of a presentation token (ZK proof). If not supported by the specific signing scheme, an
     * UnsupportedOperationException will be thrown.
     * @param token Token to verify.
     * @param avk Aggregated verification key.
     * @param m Message that was signed.
     * @param revealedAttributes Revealed attributes.
     * @return True if the token is valid w.r.t verification key, message signed and revealed attributes, false in other case.
     */
     boolean verifyZKtoken(MSzkToken token, MSverfKey avk, String m, MSmessage revealedAttributes);

}
