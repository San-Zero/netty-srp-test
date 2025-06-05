package org.let02.srp;

public interface AuthenticationListener {

    void onAuthenticationSuccess(byte[] sessionKey);
}