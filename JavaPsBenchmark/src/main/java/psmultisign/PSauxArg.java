package psmultisign;

import multisign.MSauxArg;

import java.util.Set;

/**
 * Specific auxiliary arguments needed for PS scheme setup.
 */
public class PSauxArg implements MSauxArg {
    private String pairingName;
    private Set<String> attributeNames;

    public PSauxArg(String pairingName, Set<String> attributes) {
        this.pairingName = pairingName;
        this.attributeNames = attributes;
    }

    public String getPairingName() {
        return pairingName;
    }

    public Set<String> getAttributeNames() {
        return attributeNames;
    }
}
