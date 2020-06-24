package unit.multisingMock;

import exceptions.MSSetupException;
import utils.Pair;
import multisign.*;

import java.util.Set;

public class MockMs implements MS {


    @Override
    public MSpublicParam setup(int n, MSauxArg aux) throws MSSetupException {
        return null;
    }

    @Override
    public Pair<MSprivateKey, MSverfKey> kg() {
        return null;
    }

    @Override
    public MSverfKey kAggr(MSverfKey[] vks) {
        return null;
    }

    @Override
    public MSsignature sign(MSprivateKey sk, MSmessage m) {
        return null;
    }

    @Override
    public MSsignature comb(MSverfKey[] vks, MSsignature[] signs) {
        return null;
    }

    @Override
    public boolean verf(MSverfKey avk, MSmessage m, MSsignature sign) {
        return false;
    }

    @Override
    public MSzkToken presentZKtoken(MSverfKey avk, Set<String> revealedAttributes, MSmessage attributes, String m, MSsignature sign) {
        return null;
    }

    @Override
    public boolean verifyZKtoken(MSzkToken token, MSverfKey avk, String m, MSmessage revealedAttributes) {
        return false;
    }
}