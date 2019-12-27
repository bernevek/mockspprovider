package com.imprivata.saml.service;

import org.opensaml.core.xml.io.MarshallingException;
import org.springframework.ui.Model;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public interface SsoSamlService {

    Model createPostAuthnRequest(Model model, String entityId) throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException;

    Model createSignedPostAuthnRequest(Model model, String entityId) throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException;

    String createRedirectAuthnRequest(String entityId) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, MarshallingException, IOException;

    String createSignedRedirectAuthnRequest(String entityId) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, MarshallingException, IOException;

    void setSessionIndex(String sessionIndex);

    void addSessionIndex(String entityId, String sessionIndex);

    Model createPostLogoutRequest(Model model, String entityId) throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException;

    Model createSignedPostLogoutRequest(Model model, String entityId) throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException;
}
