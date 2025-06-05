package org.let02.server;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;

public class UserDatabase {

    private final ConcurrentHashMap<String, UserCredentials> users = new ConcurrentHashMap<>();

    public void addUser(String username, byte[] salt, BigInteger verifier) {
        users.put(username, new UserCredentials(username, salt, verifier));
    }

    public UserCredentials getUser(String username) {
        return users.get(username);
    }

    public boolean userExists(String username) {
        return users.containsKey(username);
    }
}