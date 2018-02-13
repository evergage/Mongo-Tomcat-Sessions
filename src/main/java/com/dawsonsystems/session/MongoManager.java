/*x*********************************************************************************************************************
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

import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.ReadPreference;
import com.mongodb.ServerAddress;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.result.DeleteResult;
import org.apache.catalina.*;
import org.apache.catalina.session.StandardSession;
import org.bson.BsonDocument;
import org.bson.Document;
import org.bson.conversions.Bson;

import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Filters.lt;
import static com.mongodb.client.model.Projections.include;

public class MongoManager implements Manager, Lifecycle {

  private static Logger log = Logger.getLogger("MongoManager");

  private static final String COLLECTION_NAME = "sessions";

  private static String host = "localhost";
  private static int port = 27017;
  private static String database = "sessions";
  private static int connectionsPerHost = 5;

  private MongoClient mongo;
  private MongoDatabase db;
  private boolean slaveOk;

  private MongoSessionTrackerValve trackerValve;
  private ThreadLocal<StandardSession> currentSession = new ThreadLocal<>();
  private Serializer serializer;

  //Either 'kryo' or 'java'
  private String serializationStrategyClass = JavaSerializer.class.getName();

  private Context context;
  private SessionIdGenerator sessionIdGenerator;
  private int maxInactiveInterval;
  private String localHostName;

  @Override
  public Context getContext() {
    return context;
  }

  @Override
  public void setContext(Context context) {
    this.context = context;
  }

  @Override
  public SessionIdGenerator getSessionIdGenerator() {
    return sessionIdGenerator;
  }

  @Override
  public void setSessionIdGenerator(SessionIdGenerator sessionIdGenerator) {
    this.sessionIdGenerator = sessionIdGenerator;
  }

  @Override
  public void changeSessionId(Session session, String id) {
    session.setId(id);
  }

  @SuppressWarnings("WeakerAccess")
  public int getMaxInactiveInterval() {
    return maxInactiveInterval;
  }

  public void setMaxInactiveInterval(int i) {
    maxInactiveInterval = i;
  }

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

  @Override
  public void setExpiredSessions(long i) {
  }

  public int getRejectedSessions() {
    return 0;
  }

  public void setSerializationStrategyClass(String strategy) {
    this.serializationStrategyClass = strategy;
  }

  public void setSlaveOk(boolean slaveOk) {
    this.slaveOk = slaveOk;
  }

  public boolean getSlaveOk() {
    return slaveOk;
  }

  public void setRejectedSessions(int i) {
  }

  @Override
  public int getSessionMaxAliveTime() {
    return 0;
  }

  @Override
  public void setSessionMaxAliveTime(int i) {
  }

  @Override
  public int getSessionAverageAliveTime() {
    return 0;
  }

  public void setSessionAverageAliveTime(int i) {
  }

  public void load() {
  }

  public void unload() {
  }

  @Override
  public void backgroundProcess() {
    processExpires();
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
    session.setId(generateSessionId());
  }

  @Override
  public Session createEmptySession() {
    MongoSession session = new MongoSession(this);
    session.setId(generateSessionId());
    session.setMaxInactiveInterval(maxInactiveInterval);
    session.setValid(true);
    session.setCreationTime(System.currentTimeMillis());
    session.setNew(true);
    currentSession.set(session);
    log.fine("Created new empty session " + session.getIdInternal());
    return session;
  }

  private String generateSessionId() {
    return UUID.randomUUID().toString();
  }

  public Session createSession(java.lang.String sessionId) {
    StandardSession session = (MongoSession) createEmptySession();

    log.fine("Created session with id " + session.getIdInternal() + " ( " + sessionId + ")");
    if (sessionId != null) {
      session.setId(sessionId);
    }

    return session;
  }

  public Session[] findSessions() {
    try {
      List<Session> sessions = new ArrayList<>();
      for(String sessionId : keys()) {
        sessions.add(loadSession(sessionId));
      }
      return sessions.toArray(new Session[sessions.size()]);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }

  private StandardSession getNewSession() {
    log.fine("getNewSession()");
    return (MongoSession) createEmptySession();
  }

  public void start() throws LifecycleException {
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
    } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
      log.log(Level.SEVERE, "Unable to load serializer", e);
      throw new LifecycleException(e);
    }
    log.info("Will expire sessions after " + maxInactiveInterval + " seconds");
    initDbConnection(context.getPath());
  }

  public void stop() {
    if (mongo != null) {
      mongo.close();
    }
  }

  public Session findSession(String id) throws IOException {
    return loadSession(id);
  }

  @SuppressWarnings("WeakerAccess")
  public static String getHost() {
    return host;
  }

  public static void setHost(String host) {
    MongoManager.host = host;
  }

  @SuppressWarnings("WeakerAccess")
  public static int getPort() {
    return port;
  }

  public static void setPort(int port) {
    MongoManager.port = port;
  }

  @SuppressWarnings("WeakerAccess")
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

  public void clear() {
    getCollection().drop();
    getCollection().createIndex(new BasicDBObject("lastmodified", 1));
  }

  private MongoCollection<Document> getCollection() {
    return db.getCollection(COLLECTION_NAME);
  }

  public int getSize() throws IOException {
    return (int) getCollection().count();
  }

  private String[] keys() {
    MongoCursor<String> cursor = getCollection()
            .find(new BsonDocument())
            .projection(include("_id"))
            .map(doc -> (String) doc.get("_id"))
            .iterator();

    List<String> ids = new ArrayList<>();
    while (cursor.hasNext()) {
      ids.add(cursor.next());
    }
    return ids.toArray(new String[ids.size()]);
  }

  private Session loadSession(String id) throws IOException {

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

      Document dbsession = getCollection().find(eq("_id", id)).first();

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

      if (session.getThisAccessedTimeInternal() + session.getMaxInactiveInterval() * 1000 < System.currentTimeMillis()) {
        log.fine("Session " + id + " was found in Mongo but expired");
        StandardSession ret = getNewSession();
        ret.setId(id);
        currentSession.set(ret);
        return ret;
      }

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
      dbsession.put("data", data);
      if (localHostName != null) {
        dbsession.put("lasthost", localHostName);
      }
      dbsession.put("lastmodified", System.currentTimeMillis());

      Bson filter = eq("_id", standardsession.getIdInternal());
      getCollection().updateOne(filter, dbsession, new UpdateOptions().upsert(true));
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

    try {
      getCollection().deleteOne(eq("_id", session.getId()));
    } catch (RuntimeException e) {
      log.log(Level.SEVERE, "Error removing session in Mongo Session Store", e);
    } finally {
      currentSession.remove();
    }
  }

  @Override
  public void removePropertyChangeListener(PropertyChangeListener propertyChangeListener) {
    //To change body of implemented methods use File | Settings | File Templates.
  }

  private void processExpires() {
    long olderThan = System.currentTimeMillis() - (getMaxInactiveInterval() * 1000);
    log.fine("Looking for sessions less than for expiry in Mongo : " + olderThan);

    try {
      DeleteResult result = getCollection().deleteMany(lt("lastmodified", olderThan));
      log.fine("Expired sessions : " + result.getDeletedCount());
    } catch (RuntimeException e) {
      log.log(Level.SEVERE, "Error cleaning session in Mongo Session Store", e);
    }
  }

  private void initDbConnection(String path) throws LifecycleException {
    try {
      String[] hosts = getHost().split(",");

      List<ServerAddress> addrs = new ArrayList<>();

      for (String host : hosts) {
        addrs.add(new ServerAddress(host, getPort()));
      }

      mongo = new MongoClient(addrs,
                              MongoClientOptions.builder()
              .description("TomcatMongoSession[path=" + path + "]")
              .alwaysUseMBeans(true)
              .connectionsPerHost(connectionsPerHost)
              .build());

      db = mongo.getDatabase(getDatabase());
      if (slaveOk) {
        db.withReadPreference(ReadPreference.secondaryPreferred());
      }
      db.withWriteConcern(WriteConcern.ACKNOWLEDGED);
      getCollection().createIndex(new BasicDBObject("lastmodified", 1));
      log.info("Connected to Mongo " + host + "/" + database + " for session storage, slaveOk=" + slaveOk + ", " + (getMaxInactiveInterval() * 1000) + " session live time");
    } catch (RuntimeException e) {
      e.printStackTrace();
      throw new LifecycleException("Error Connecting to Mongo", e);
    }
  }

  private void initSerializer() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
    log.info("Attempting to use serializer :" + serializationStrategyClass);
    serializer = (Serializer) Class.forName(serializationStrategyClass).newInstance();

    Loader loader = null;

    if (context != null) {
      loader = context.getLoader();
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
  public void init() {
    // nada
  }

  @Override
  public void destroy() {
    // nada
  }

  @Override
  public LifecycleState getState() {
    return (db == null) ? LifecycleState.NEW : LifecycleState.STARTED;
  }

  @Override
  public String getStateName() {
    return getState().toString();
  }

}
