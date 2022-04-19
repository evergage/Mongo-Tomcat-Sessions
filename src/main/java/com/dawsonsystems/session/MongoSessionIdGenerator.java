package com.dawsonsystems.session;

import org.apache.catalina.SessionIdGenerator;

import java.util.UUID;

/**
 * From Tomcat 8.5.76 we have to use subclass of SessionIdGenerator with some overriding methods.
 */
public class MongoSessionIdGenerator implements SessionIdGenerator {

    private String jvmRoute = "";

    @Override
    public String getJvmRoute() {
        return this.jvmRoute;
    }

    @Override
    public void setJvmRoute(String jvmRoute) {
        this.jvmRoute = jvmRoute;
    }

    @Override
    public int getSessionIdLength() {
        return 37;
    }

    @Override
    public void setSessionIdLength(int sessionIdLength) {
    }

    @Override
    public String generateSessionId() {
        return UUID.randomUUID().toString();
    }

    @Override
    public String generateSessionId(String route) {
        return generateSessionId();
    }
}
