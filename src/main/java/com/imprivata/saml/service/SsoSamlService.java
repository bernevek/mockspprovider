package com.imprivata.saml.service;

import org.opensaml.core.xml.io.MarshallingException;
import org.springframework.ui.Model;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public interface SsoSamlService {

    Model createPostAuthnRequest(Model model) throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException;

    Model createSignedPostAuthnRequest(Model model) throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException;

    String createRedirectAuthnRequest() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, MarshallingException, IOException;

    String createSignedRedirectAuthnRequest() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, MarshallingException, IOException;

    void setSessionIndex(String sessionIndex);

    Model createPostLogoutRequest(Model model) throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException;

    Model createSignedPostLogoutRequest(Model model) throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException;

}
