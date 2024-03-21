/*
 * Copyright 2010-2022 salesforce.com, inc.
 * All Rights Reserved. Company Confidential.
 */

package com.dawsonsystems.session;

import com.google.common.base.Preconditions;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;

public class InstantSwappableX509ExtendedKeyManager extends X509ExtendedKeyManager {
    private AtomicReference<X509ExtendedKeyManager> delegate;

    public InstantSwappableX509ExtendedKeyManager(X509ExtendedKeyManager delegate) {
        Preconditions.checkArgument(delegate != null, "delegate must not be null");
        this.delegate = new AtomicReference<>(delegate);
    }

    public void setDelegate(X509ExtendedKeyManager delegate) {
        Preconditions.checkArgument(delegate != null, "delegate must not be null");
        this.delegate.set(delegate);
    }

    @Override
    public String chooseEngineClientAlias(
            String[] keyType, Principal[] issuers, SSLEngine engine) {
        return delegate.get().chooseEngineClientAlias(keyType, issuers, engine);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return delegate.get().chooseEngineServerAlias(keyType, issuers, engine);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return delegate.get().getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return delegate.get().chooseClientAlias(keyType, issuers, socket);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return delegate.get().getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return delegate.get().chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return delegate.get().getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return delegate.get().getPrivateKey(alias);
    }

}
