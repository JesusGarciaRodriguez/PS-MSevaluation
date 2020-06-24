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
import com.ibm.zurich.idmx.interfaces.orchestration.issuance.StateIssuer;
import com.ibm.zurich.idmx.interfaces.orchestration.issuance.StateRecipient;
import com.ibm.zurich.idmx.interfaces.orchestration.issuance.StateStorage;
import com.ibm.zurich.idmx.orchestration.issuance.StateStorageMapIssuer;
import com.ibm.zurich.idmx.orchestration.issuance.StateStorageMapRecipient;

/**
 * Use this module if you want the state for issuance (issuer and recipient) to be
 * stored in memory in a map.
 * This is faster than the persistent storage, since the state is not serialized
 * or deserialized.
 * @author enr
 *
 */
public class StateStorageInMemory extends AbstractModule {

  @Override
  protected void configure() {
    this.bind(new TypeLiteral<StateStorage<StateIssuer>>() {}).to(StateStorageMapIssuer.class)
        .in(Singleton.class);
    this.bind(new TypeLiteral<StateStorage<StateRecipient>>() {})
        .to(StateStorageMapRecipient.class).in(Singleton.class);
  }

}
