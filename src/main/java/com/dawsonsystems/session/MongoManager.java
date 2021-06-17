/***********************************************************************************************************************
 *
 * Mongo Tomcat Sessions
 * ==========================================
 *
 * Copyright (C) 2012 by Dawson Systems Ltd (http://www.dawsonsystems.com)
 *
 ***********************************************************************************************************************
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 **********************************************************************************************************************/

package com.dawsonsystems.session;

import com.mongodb.*;
import com.mongodb.MongoClientOptions.Builder;
import org.apache.catalina.*;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.session.StandardSession;

import javax.net.ssl.SSLContext;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.catalina.session.ManagerBase;

import static com.dawsonsystems.session.ClientSSLFromPEMsUtility.sslContextFromPEMs;

public class MongoManager extends ManagerBase implements Lifecycle {
  private static Logger log = Logger.getLogger("MongoManager");
  protected static String host = "localhost";
  protected static int port = 27017;
  protected static String database = "sessions";
  protected static int connectionsPerHost = 5;
  protected MongoClient mongo;
  protected DB db;
  protected boolean slaveOk;

  private MongoSessionTrackerValve trackerValve;
  private ThreadLocal<StandardSession> currentSession = new ThreadLocal<StandardSession>();
  private Serializer serializer;

  //Either 'kryo' or 'java'
  private String serializationStrategyClass = "com.dawsonsystems.session.JavaSerializer";

  private String localHostName;

  // Mongo client SSL support directly from PEM bundles
  private String sslKeyStorePem;
  private String sslTrustStorePem;

  @Override
  public long getSessionCounter() {
    return 10000000;
  }

  @Override
  public void setSessionCounter(long i) {

  }

  @Override
  public int getMaxActive() {
    return 1000000;
  }

  @Override
  public void setMaxActive(int i) {

  }

  @Override
  public int getActiveSessions() {
    return 1000000;
  }

  @Override
  public long getExpiredSessions() {
    return 0;
  }

  public void addLifecycleListener(LifecycleListener lifecycleListener) {
  }

  public LifecycleListener[] findLifecycleListeners() {
    return new LifecycleListener[0];  //To change body of implemented methods use File | Settings | File Templates.
  }

  public void removeLifecycleListener(LifecycleListener lifecycleListener) {
  }

  @Override
  public void add(Session session) {
    try {
      save(session);
    } catch (IOException ex) {
      log.log(Level.SEVERE, "Error adding new session", ex);
    }
  }

  @Override
  public void addPropertyChangeListener(PropertyChangeListener propertyChangeListener) {
    //To change body of implemented methods use File | Settings | File Templates.
  }

  @Override
  public void changeSessionId(Session session) {
    session.setId(UUID.randomUUID().toString());
  }

  @Override
  public Session createEmptySession() {
    MongoSession session = new MongoSession(this);
    session.setId(UUID.randomUUID().toString());
    session.setMaxInactiveInterval(getSessionMaxAliveTime());
    session.setValid(true);
    session.setCreationTime(System.currentTimeMillis());
    session.setNew(true);
    currentSession.set(session);
    log.fine("Created new empty session " + session.getIdInternal());
    return session;
  }

  /**
   * @deprecated
   */
  public org.apache.catalina.Session createSession() {
    return createEmptySession();
  }

  public org.apache.catalina.Session createSession(java.lang.String sessionId) {
    StandardSession session = (MongoSession) createEmptySession();

    log.fine("Created session with id " + session.getIdInternal() + " ( " + sessionId + ")");
    if (sessionId != null) {
      session.setId(sessionId);
    }

    return session;
  }

  public org.apache.catalina.Session[] findSessions() {
    try {
      List<Session> sessions = new ArrayList<Session>();
      for(String sessionId : keys()) {
        sessions.add(loadSession(sessionId));
      }
      return sessions.toArray(new Session[sessions.size()]);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void load() throws ClassNotFoundException, IOException {
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void unload() throws IOException {
  }

  protected org.apache.catalina.session.StandardSession getNewSession() {
    log.fine("getNewSession()");
    return (MongoSession) createEmptySession();
  }

  @Override
  protected void startInternal() throws LifecycleException {
    super.startInternal();

    try {
      localHostName = InetAddress.getLocalHost().getHostName();
    } catch (UnknownHostException e) {
      log.severe("Local host not found: " + e);
    }

    for (Valve valve : getContext().getPipeline().getValves()) {
      if (valve instanceof MongoSessionTrackerValve) {
        trackerValve = (MongoSessionTrackerValve) valve;
        trackerValve.setMongoManager(this);
        log.info("Attached to Mongo Tracker Valve");
        break;
      }
    }
    try {
      initSerializer();
    } catch (ClassNotFoundException e) {
      log.log(Level.SEVERE, "Unable to load serializer", e);
      throw new LifecycleException(e);
    } catch (InstantiationException e) {
      log.log(Level.SEVERE, "Unable to load serializer", e);
      throw new LifecycleException(e);
    } catch (IllegalAccessException e) {
      log.log(Level.SEVERE, "Unable to load serializer", e);
      throw new LifecycleException(e);
    }
    log.info("Will expire sessions after " + getSessionMaxAliveTime() + " seconds");
    initDbConnection(getPath());

    setState(LifecycleState.STARTING);
  }

  private String getPath() {
    if (getContext() instanceof StandardContext) {
      return ((StandardContext) getContext()).getPath();
    } else {
      return "<Unknown>";
    }
  }

  @Override
  protected void stopInternal() throws LifecycleException {
    setState(LifecycleState.STOPPING);
    if (mongo != null) {
      mongo.close();
    }
    log.info("Stopping");
    super.stopInternal();
  }

  public Session findSession(String id) throws IOException {
    return loadSession(id);
  }

  public static String getHost() {
    return host;
  }

  public static void setHost(String host) {
    MongoManager.host = host;
  }

  public static int getPort() {
    return port;
  }

  public static void setPort(int port) {
    MongoManager.port = port;
  }

  public static String getDatabase() {
    return database;
  }

  public static void setDatabase(String database) {
    MongoManager.database = database;
  }

  public static int getConnectionsPerHost() {
    return connectionsPerHost;
  }

  public static void setConnectionsPerHost(int connectionsPerHost) {
    MongoManager.connectionsPerHost = connectionsPerHost;
  }

  public void clear() throws IOException {
    getCollection().drop();
    getCollection().createIndex(new BasicDBObject("lastmodified", 1));
  }

  private DBCollection getCollection() throws IOException {
    return db.getCollection("sessions");
  }

  public int getSize() throws IOException {
    return (int) getCollection().count();
  }

  public String[] keys() throws IOException {

    BasicDBObject restrict = new BasicDBObject();
    restrict.put("_id", 1);

    DBCursor cursor = getCollection().find(new BasicDBObject(), restrict);

    List<String> ret = new ArrayList<String>();

    while (cursor.hasNext()) {
      ret.add(cursor.next().get("").toString());
    }

    return ret.toArray(new String[ret.size()]);
  }


  public Session loadSession(String id) throws IOException {

    if (id == null || id.length() == 0) {
      return createEmptySession();
    }

    StandardSession session = currentSession.get();

    if (session != null) {
      if (id.equals(session.getId())) {
        return session;
      } else {
        currentSession.remove();
      }
    }
    try {
      log.fine("Loading session " + id + " from Mongo");
      BasicDBObject query = new BasicDBObject();
      query.put("_id", id);

      DBObject dbsession = getCollection().findOne(query);

      if (dbsession == null) {
        log.fine("Session " + id + " not found in Mongo");
        StandardSession ret = getNewSession();
        ret.setId(id);
        currentSession.set(ret);
        return ret;
      }

      byte[] data = (byte[]) dbsession.get("data");

      session = (MongoSession) createEmptySession();
      session.setId(id);
      session.setManager(this);
      serializer.deserializeInto(data, session);

      session.setMaxInactiveInterval(-1);
      session.access();
      session.setValid(true);
      session.setNew(false);

      if (log.isLoggable(Level.FINE)) {
        log.fine("Session Contents [" + session.getId() + "]:");
        for (Object name : Collections.list(session.getAttributeNames())) {
          log.fine("  " + name);
        }
      }

      log.fine("Loaded session id " + id);
      currentSession.set(session);
      return session;
    } catch (IOException e) {
      log.severe(e.getMessage());
      throw e;
    } catch (ClassNotFoundException ex) {
      log.log(Level.SEVERE, "Unable to deserialize session ", ex);
      throw new IOException("Unable to deserializeInto session", ex);
    }
  }

  public void save(Session session) throws IOException {
    try {
      log.fine("Saving session " + session + " into Mongo");

      StandardSession standardsession = (MongoSession) session;

      if (log.isLoggable(Level.FINE)) {
        log.fine("Session Contents [" + session.getId() + "]:");
        for (Object name : Collections.list(standardsession.getAttributeNames())) {
          log.fine("  " + name);
        }
      }

      byte[] data = serializer.serializeFrom(standardsession);

      BasicDBObject dbsession = new BasicDBObject();
      dbsession.put("_id", standardsession.getId());
      dbsession.put("principalId", standardsession.getAttribute("SESSION_APPTEGIC_PRINCIPAL"));
      dbsession.put("data", data);
      if (localHostName != null) {
        dbsession.put("lasthost", localHostName);
      }
      dbsession.put("lastmodified", System.currentTimeMillis());

      BasicDBObject query = new BasicDBObject();
      query.put("_id", standardsession.getIdInternal());
      getCollection().update(query, dbsession, true, false);
      log.fine("Updated session with id " + session.getIdInternal());
    } catch (IOException e) {
      log.severe(e.getMessage());
      e.printStackTrace();
      throw e;
    } finally {
      currentSession.remove();
      log.fine("Session removed from ThreadLocal :" + session.getIdInternal());
    }
  }

  public void remove(Session session) {
    log.fine("Removing session ID : " + session.getId());
    BasicDBObject query = new BasicDBObject();
    query.put("_id", session.getId());

    try {
      getCollection().remove(query);
    } catch (IOException e) {
      log.log(Level.SEVERE, "Error removing session in Mongo Session Store", e);
    } finally {
      currentSession.remove();
    }
  }

  @Override
  public void removePropertyChangeListener(PropertyChangeListener propertyChangeListener) {
    //To change body of implemented methods use File | Settings | File Templates.
  }

  public void processExpires() {
    BasicDBObject query = new BasicDBObject();

    long olderThan = System.currentTimeMillis() - (getSessionMaxAliveTime() * 1000);

    log.fine("Looking for sessions less than for expiry in Mongo : " + olderThan);

    query.put("lastmodified", new BasicDBObject("$lt", olderThan));

    try {
      WriteResult result = getCollection().remove(query);
      log.fine("Expired sessions : " + result.getN());
    } catch (IOException e) {
      log.log(Level.SEVERE, "Error cleaning session in Mongo Session Store", e);
    }
  }

  private void initDbConnection(String path) throws LifecycleException {
    try {
      String[] hosts = getHost().split(",");

      List<ServerAddress> addrs = new ArrayList<ServerAddress>();

      for (String host : hosts) {
        addrs.add(new ServerAddress(host, getPort()));
      }

      Builder clientOptionsBuilder = MongoClientOptions.builder()
              .description("TomcatMongoSession[path=" + path + "]")
              .alwaysUseMBeans(true)
              .connectionsPerHost(connectionsPerHost);

      List<MongoCredential> mongoCredentials = new ArrayList<>();

      if (sslTrustStorePem != null && sslTrustStorePem.length() > 0 && sslKeyStorePem != null && sslKeyStorePem.length() > 0) {
        log.info("Detected Mongo SSL configuration: trust store PEM: " + sslTrustStorePem + ", key store PEM: " + sslKeyStorePem);
        SSLContext sslContext = sslContextFromPEMs(new File(sslTrustStorePem), new File(sslKeyStorePem));
        clientOptionsBuilder.sslEnabled(true);
        clientOptionsBuilder.sslContext(sslContext);
        mongoCredentials.add(MongoCredential.createMongoX509Credential());
      } else {
        log.info("Using an unencrypted connection to Mongo");
      }

      mongo = new MongoClient(addrs, mongoCredentials, clientOptionsBuilder.build());

      db = mongo.getDB(getDatabase());
      if (slaveOk) {
        db.setReadPreference(ReadPreference.secondaryPreferred());
      }
      db.setWriteConcern(WriteConcern.ACKNOWLEDGED);
      getCollection().createIndex(new BasicDBObject("lastmodified", 1));
      log.info("Connected to Mongo " + host + "/" + database + " for session storage, slaveOk=" + slaveOk + ", " + (getSessionMaxAliveTime() * 1000) + " session live time");
    } catch (RuntimeException | IOException e) {
      e.printStackTrace();
      throw new LifecycleException("Error Connecting to Mongo", e);
    }
  }

  private void initSerializer() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
    log.info("Attempting to use serializer :" + serializationStrategyClass);
    serializer = (Serializer) Class.forName(serializationStrategyClass).newInstance();

    Loader loader = null;

    if (getContext() != null) {
      loader = getContext().getLoader();
    }
    ClassLoader classLoader = null;

    if (loader != null) {
      classLoader = loader.getClassLoader();
    }
    serializer.setClassLoader(classLoader);
  }

  @Override
  public int getSessionCreateRate() {
    return 0;
  }

  @Override
  public int getSessionExpireRate() {
    return 0;
  }

  @Override
  public void remove(Session session, boolean update) {
    remove(session);
  }

  @Override
  public boolean willAttributeDistribute(String name, Object value) {
    return true;
  }

  @Override
  public LifecycleState getState() {
    return db == null ? LifecycleState.NEW : LifecycleState.STARTED;
  }

  @Override
  public String getStateName() {
    return getState().toString();
  }
}
