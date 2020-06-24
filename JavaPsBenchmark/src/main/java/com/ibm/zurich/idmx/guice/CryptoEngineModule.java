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
import com.google.inject.TypeLiteral;
import com.ibm.zurich.idmx.buildingBlock.factory.BuildingBlockFactory;
import com.ibm.zurich.idmx.buildingBlock.revocation.StateStorageMapRevocationAuthority;
import com.ibm.zurich.idmx.cryptoEngine.CryptoEngineInspectorImpl;
import com.ibm.zurich.idmx.cryptoEngine.CryptoEngineIssuerImpl;
import com.ibm.zurich.idmx.cryptoEngine.CryptoEngineProverImpl;
import com.ibm.zurich.idmx.cryptoEngine.CryptoEngineRecipientImpl;
import com.ibm.zurich.idmx.cryptoEngine.CryptoEngineRevocationAuthorityImpl;
import com.ibm.zurich.idmx.cryptoEngine.CryptoEngineVerifierImpl;
import com.ibm.zurich.idmx.interfaces.buildingBlock.revocation.StateRevocationAuthority;
import com.ibm.zurich.idmx.interfaces.cryptoEngine.CryptoEngineInspector;
import com.ibm.zurich.idmx.interfaces.cryptoEngine.CryptoEngineIssuer;
import com.ibm.zurich.idmx.interfaces.cryptoEngine.CryptoEngineProver;
import com.ibm.zurich.idmx.interfaces.cryptoEngine.CryptoEngineRecipient;
import com.ibm.zurich.idmx.interfaces.cryptoEngine.CryptoEngineRevocationAuthority;
import com.ibm.zurich.idmx.interfaces.cryptoEngine.CryptoEngineVerifier;
import com.ibm.zurich.idmx.interfaces.orchestration.KeyGenerationOrchestration;
import com.ibm.zurich.idmx.interfaces.orchestration.issuance.IssuanceOrchestrationIssuer;
import com.ibm.zurich.idmx.interfaces.orchestration.issuance.IssuanceOrchestrationRecipient;
import com.ibm.zurich.idmx.interfaces.orchestration.issuance.IssuanceOrchestrationRevocationAuthority;
import com.ibm.zurich.idmx.interfaces.orchestration.issuance.StateStorage;
import com.ibm.zurich.idmx.interfaces.orchestration.presentation.PresentationOrchestrationInspector;
import com.ibm.zurich.idmx.interfaces.orchestration.presentation.PresentationOrchestrationProver;
import com.ibm.zurich.idmx.interfaces.orchestration.presentation.PresentationOrchestrationVerifier;
import com.ibm.zurich.idmx.interfaces.proofEngine.ZkDirector;
import com.ibm.zurich.idmx.interfaces.util.BigIntFactory;
import com.ibm.zurich.idmx.interfaces.util.RandomGeneration;
import com.ibm.zurich.idmx.interfaces.util.Timing;
import com.ibm.zurich.idmx.interfaces.util.group.GroupFactory;
import com.ibm.zurich.idmx.orchestration.KeyGenerationOrchestrationImpl;
import com.ibm.zurich.idmx.orchestration.issuance.IssuanceOrchestrationIssuerImpl;
import com.ibm.zurich.idmx.orchestration.issuance.IssuanceOrchestrationRecipientImpl;
import com.ibm.zurich.idmx.orchestration.issuance.IssuanceOrchestrationRevocationAuthorityImpl;
import com.ibm.zurich.idmx.orchestration.presentation.PresentationOrchestrationInspectorImpl;
import com.ibm.zurich.idmx.orchestration.presentation.PresentationOrchestrationProverImpl;
import com.ibm.zurich.idmx.orchestration.presentation.PresentationOrchestrationVerifierImpl;
import com.ibm.zurich.idmx.proofEngine.ZkDirectorImpl;
import com.ibm.zurich.idmx.util.RandomGenerationImpl;
import com.ibm.zurich.idmx.util.TimingImpl;
import com.ibm.zurich.idmx.util.bigInt.BigIntFactoryImpl;
import com.ibm.zurich.idmx.util.group.GroupFactoryImpl;


class CryptoEngineModule extends AbstractModule {

  @Override
  protected void configure() {
    // Crypto architecture components

    // --> Utilities
    this.bind(RandomGeneration.class).to(RandomGenerationImpl.class).in(Singleton.class);
    this.bind(Timing.class).to(TimingImpl.class).in(Singleton.class);
    this.bind(BigIntFactory.class).to(BigIntFactoryImpl.class).in(Singleton.class);
    this.bind(GroupFactory.class).to(GroupFactoryImpl.class).in(Singleton.class);

    // --> Classes for several parties
    this.bind(BuildingBlockFactory.class).in(Singleton.class);
    this.bind(ZkDirector.class).to(ZkDirectorImpl.class).in(Singleton.class);

    // --> Credential issuer classes
    this.bind(CryptoEngineIssuer.class).to(CryptoEngineIssuerImpl.class).in(Singleton.class);
    this.bind(KeyGenerationOrchestration.class).to(KeyGenerationOrchestrationImpl.class)
        .in(Singleton.class);
    this.bind(IssuanceOrchestrationIssuer.class).to(IssuanceOrchestrationIssuerImpl.class)
        .in(Singleton.class);


    // --> Credential recipient classes
    this.bind(CryptoEngineRecipient.class).to(CryptoEngineRecipientImpl.class).in(Singleton.class);
    this.bind(IssuanceOrchestrationRecipient.class).to(IssuanceOrchestrationRecipientImpl.class)
        .in(Singleton.class);

    // --> Credential presentation prover
    this.bind(CryptoEngineProver.class).to(CryptoEngineProverImpl.class).in(Singleton.class);
    this.bind(PresentationOrchestrationProver.class).to(PresentationOrchestrationProverImpl.class)
        .in(Singleton.class);

    // --> Credential presentation verifier
    this.bind(CryptoEngineVerifier.class).to(CryptoEngineVerifierImpl.class).in(Singleton.class);
    this.bind(PresentationOrchestrationVerifier.class)
        .to(PresentationOrchestrationVerifierImpl.class).in(Singleton.class);

    // --> Revocation authority
    this.bind(CryptoEngineRevocationAuthority.class).to(CryptoEngineRevocationAuthorityImpl.class)
        .in(Singleton.class);
    this.bind(IssuanceOrchestrationRevocationAuthority.class)
        .to(IssuanceOrchestrationRevocationAuthorityImpl.class).in(Singleton.class);
    this.bind(new TypeLiteral<StateStorage<StateRevocationAuthority>>() {})
        .to(StateStorageMapRevocationAuthority.class).in(Singleton.class);
    
    // --> Inspector
    this.bind(CryptoEngineInspector.class).to(CryptoEngineInspectorImpl.class).in(Singleton.class);
    this.bind(PresentationOrchestrationInspector.class)
        .to(PresentationOrchestrationInspectorImpl.class).in(Singleton.class);

    //install(new StateStorageInMemory());
    install(new StateStorageInMemory());
  }

}
