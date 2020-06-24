//* Licensed Materials - Property of IBM                                     *
//* com.ibm.zurich.idmx.3_x_x                                                *
//* (C) Copyright IBM Corp. 2015. All Rights Reserved.                       *
//* US Government Users Restricted Rights - Use, duplication or              *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp.        *
//*                                                                          *
//* The contents of this file are subject to the terms of either the         *
//* International License Agreement for Identity Mixer Version 1.2 or the    *
//* Apache License Version 2.0.                                              *
//*                                                                          *
//* The license terms can be found in the file LICENSE.txt that is provided  *
//* together with this software.                                             *
//*/**/***********************************************************************
package com.ibm.zurich.idmx.guice;

import com.google.inject.AbstractModule;
import com.google.inject.Singleton;
import com.ibm.zurich.idmix.abc4trust.cryptoEngine.Abc4TrustCryptoEngineInspectorImpl;
import com.ibm.zurich.idmix.abc4trust.cryptoEngine.Abc4TrustCryptoEngineIssuerImpl;
import com.ibm.zurich.idmix.abc4trust.cryptoEngine.Abc4TrustCryptoEngineRevocationImpl;
import com.ibm.zurich.idmix.abc4trust.cryptoEngine.Abc4TrustCryptoEngineUserImpl;
import com.ibm.zurich.idmix.abc4trust.cryptoEngine.Abc4TrustCryptoEngineVerifierImpl;
import com.ibm.zurich.idmx.buildingBlock.factory.BuildingBlockList;
import com.ibm.zurich.idmx.buildingBlock.factory.BuildingBlockListAbc4trust;

public class Abc4trustModule extends AbstractModule{
  @Override
  protected void configure() {
    install(new CryptoEngineModule());
    this.bind(BuildingBlockList.class).to(BuildingBlockListAbc4trust.class).in(Singleton.class);
    this.bind(eu.abc4trust.cryptoEngine.user.CryptoEngineUser.class)
    .to(Abc4TrustCryptoEngineUserImpl.class).in(Singleton.class);
    this.bind(eu.abc4trust.cryptoEngine.verifier.CryptoEngineVerifier.class)
    .to(Abc4TrustCryptoEngineVerifierImpl.class).in(Singleton.class);
    this.bind(eu.abc4trust.cryptoEngine.inspector.CryptoEngineInspector.class)
    .to(Abc4TrustCryptoEngineInspectorImpl.class).in(Singleton.class);
    this.bind(eu.abc4trust.cryptoEngine.revocation.CryptoEngineRevocation.class)
    .to(Abc4TrustCryptoEngineRevocationImpl.class).in(Singleton.class);
    this.bind(eu.abc4trust.cryptoEngine.issuer.CryptoEngineIssuer.class)
    .to(Abc4TrustCryptoEngineIssuerImpl.class).in(Singleton.class);
  }
}
