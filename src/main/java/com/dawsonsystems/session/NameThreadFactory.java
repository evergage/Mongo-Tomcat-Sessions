/*
 * Copyright (C) 2010-2011 Apptegic, Inc.
 * All rights reserved.
 */

package com.dawsonsystems.session;

import javax.annotation.Nonnull;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * @author Greg Hinkle
 */
public class NameThreadFactory implements ThreadFactory {

    private String id;
    private AtomicInteger index = new AtomicInteger(1);
    private final ThreadGroup group;
    private boolean daemon;
    private int threadPriority = Thread.NORM_PRIORITY;

    protected NameThreadFactory(String id) {
        this.id = id;
        SecurityManager securityManager = System.getSecurityManager();
        group = (securityManager != null) ? securityManager.getThreadGroup() : Thread.currentThread().getThreadGroup();
    }

    /**
     * Prefer daemon over nonDaemon when creating new thread pools.
     */
    public static NameThreadFactory daemon(String id) {
        NameThreadFactory factory = new NameThreadFactory(id);
        factory.daemon = true;
        return factory;
    }

    public static NameThreadFactory nonDaemon(String id) {
        return new NameThreadFactory(id);
    }

    public NameThreadFactory withPriority(int threadPriority) {
        checkArgument(threadPriority <= Thread.MAX_PRIORITY, "Thread priority must be no greater than %s", Thread.MAX_PRIORITY);
        checkArgument(threadPriority >= Thread.MIN_PRIORITY, "Thread priority must be no less than %s", Thread.MIN_PRIORITY);
        this.threadPriority = threadPriority;
        return this;
    }

    @Override
    public Thread newThread(@Nonnull Runnable r) {
        Thread t = new Thread(group, r, id + "_" + index.getAndIncrement(), 0);
        t.setDaemon(daemon);
        t.setPriority(threadPriority);

        return t;
    }

    private static String getNameThreadFactoryId(String threadPoolSettingsId) {
        return threadPoolSettingsId;
    }

}
