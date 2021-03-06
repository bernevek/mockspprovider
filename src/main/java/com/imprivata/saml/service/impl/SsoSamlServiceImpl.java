package com.imprivata.saml.service.impl;

import com.imprivata.saml.model.SamlNameIdFormatEnum;
import com.imprivata.saml.model.SamlProtocolBinding;
import com.imprivata.saml.model.SingleLogoutService;
import com.imprivata.saml.model.SingleSignOnService;
import com.imprivata.saml.service.MetadataService;
import com.imprivata.saml.service.SsoSamlService;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.w3c.dom.Element;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

@Service
public class SsoSamlServiceImpl implements SsoSamlService {

    @Value("${currentHost}")
    private String currentHost;

    @Value("${encriptedPrivateKey}")
    public String encriptedPrivateKey;

    @Value("${publicKeyPemCertificate}")
    public String publicKeyPemCertificate;

    @Autowired
    private MetadataService metadataService;

    private AuthnRequestBuilder authnRequestBuilder;
    private LogoutRequestBuilder logoutRequestBuilder;
    private MarshallerFactory marshallerFactory;
    private XMLObjectBuilderFactory builderFactory;
    private PrivateKey privateKey;
    private X509Certificate x509Certificate;
    private String sessionIndex = null;
    private Map<String, String> sessionIndexes;

    @PostConstruct
    public void basicRequestsInitialization() throws Base64DecodingException, InvalidKeySpecException,
        NoSuchAlgorithmException, CertificateException, InitializationException {
        InitializationService.initialize();

        privateKey = getPrivateKey(encriptedPrivateKey);

        x509Certificate = getX509Certificate();

        builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        authnRequestBuilder = (AuthnRequestBuilder) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        logoutRequestBuilder = (LogoutRequestBuilder) builderFactory.getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
        marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        sessionIndexes = new HashMap<>();
    }

    private RequestAbstractType initRequest(RequestAbstractType request, String requestId) {
        request.setIssueInstant(new DateTime());
        request.setID(requestId == null ? "ONELOGIN_" + UUID.randomUUID().toString() : requestId);
        request.setVersion(SAMLVersion.VERSION_20);
        Issuer issuer = ((IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
        issuer.setValue(currentHost);
        request.setIssuer(issuer);
        if (request instanceof AuthnRequest) {
            ((AuthnRequest) request).setForceAuthn(false);
            ((AuthnRequest) request).setIsPassive(false);
            ((AuthnRequest) request).setAssertionConsumerServiceIndex(0);
            ((AuthnRequest) request).setAttributeConsumingServiceIndex(0);
            NameIDPolicy nameIDPolicy = ((NameIDPolicyBuilder) builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME)).buildObject();
            nameIDPolicy.setAllowCreate(true);
            nameIDPolicy.setFormat(SamlNameIdFormatEnum.UNSPECIFIED.getName());
            ((AuthnRequest) request).setNameIDPolicy(nameIDPolicy);
        }
        if (request instanceof LogoutRequest) {
            NameID nameID = ((NameIDBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
            nameID.setFormat(SamlNameIdFormatEnum.UNSPECIFIED.getName());
            ((LogoutRequest) request).setNameID(nameID);
        }
        return request;
    }

    @Override
    public Model createPostAuthnRequest(Model model, String entityId, String requestId) throws MarshallingException,
        IOException, org.opensaml.xmlsec.signature.support.SignatureException {
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
        return getPostRequest(false, model, initRequest(authnRequest, requestId), entityId);
    }

    @Override
    public Model createSignedPostAuthnRequest(Model model, String entityId, String requestId)
        throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException {
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
        return getPostRequest(true, model, initRequest(authnRequest, requestId), entityId);
    }

    @Override
    public String createRedirectAuthnRequest(String entityId, String requestId) throws InvalidKeyException,
        SignatureException, NoSuchAlgorithmException, MarshallingException, IOException {
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
        return getRedirectAuthnRequestUrl(false, initRequest(authnRequest, requestId), entityId);
    }

    @Override
    public String createSignedRedirectAuthnRequest(String entityId, String requestId) throws InvalidKeyException,
        SignatureException, NoSuchAlgorithmException, MarshallingException, IOException {
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
        return getRedirectAuthnRequestUrl(true, initRequest(authnRequest, requestId), entityId);
    }

    @Override
    public void setSessionIndex(String sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    @Override
    public void addSessionIndex(String entityId, String sessionIndex) {
        this.sessionIndexes.put(entityId, sessionIndex);
    }

    @Override
    public Model createPostLogoutRequest(Model model, String entityId, String requestId) throws MarshallingException,
        IOException, org.opensaml.xmlsec.signature.support.SignatureException {
        LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
        return getPostRequest(false, model, initRequest(logoutRequest, requestId), entityId);
    }

    @Override
    public Model createSignedPostLogoutRequest(Model model, String entityId, String requestId)
        throws MarshallingException, IOException, org.opensaml.xmlsec.signature.support.SignatureException {
        LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
        return getPostRequest(true, model, initRequest(logoutRequest, requestId), entityId);
    }

    @Override
    public String createRedirectLogoutRequest(String entityId, String requestId) throws InvalidKeyException,
        SignatureException, NoSuchAlgorithmException, MarshallingException, IOException {
        LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
        return getRedirectAuthnRequestUrl(false, initRequest(logoutRequest, requestId), entityId);
    }

    @Override
    public String createSignedRedirectLogoutRequest(String entityId, String requestId) throws InvalidKeyException,
        SignatureException, NoSuchAlgorithmException, MarshallingException, IOException {
        LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
        return getRedirectAuthnRequestUrl(true, initRequest(logoutRequest, requestId), entityId);
    }

    private Model getPostRequest(Boolean isSigned, Model model, RequestAbstractType request, String entityId)
        throws IOException, org.opensaml.xmlsec.signature.support.SignatureException, MarshallingException {
        if (request instanceof AuthnRequest) {
            SingleSignOnService ssoService = metadataService
                    .getMetadata(entityId)
                    .singleSignOnServices
                    .stream()
                    .filter(singleSignOnService -> singleSignOnService.binding.equals(SamlProtocolBinding.HTTP_POST))
                    .findFirst().orElseThrow(IOException::new);
            request.setDestination(ssoService.location);
            ((AuthnRequest)request).setAssertionConsumerServiceURL(currentHost + "/sso/post");
            model.addAttribute("PostBindingLink", ssoService.location);
        }
        if (request instanceof LogoutRequest) {
            SingleLogoutService sloService = metadataService
                    .getMetadata(entityId)
                    .singleLogoutServices
                    .stream()
                    .filter(singleLogoutService -> singleLogoutService.binding.equals(SamlProtocolBinding.HTTP_POST))
                    .findFirst().orElseThrow(IOException::new);
            request.setDestination(sloService.location);
            SessionIndex sessionIndex = ((SessionIndexBuilder) builderFactory.getBuilder(SessionIndex.DEFAULT_ELEMENT_NAME)).buildObject();
            sessionIndex.setSessionIndex(this.sessionIndexes.get(metadataService.getMetadata(entityId).entityId));
            ((LogoutRequest)request).getSessionIndexes().add(sessionIndex);
            model.addAttribute("PostBindingLink", sloService.location);
        }
        Element authnRequestDom = null;
        if (isSigned){
            BasicX509Credential x509Credential = new BasicX509Credential(x509Certificate, privateKey);
            x509Credential.setUsageType(UsageType.SIGNING);
            KeyInfo keyInfo = generateKeyInfo(x509Credential);
            org.opensaml.xmlsec.signature.Signature signature = (org.opensaml.xmlsec.signature.Signature)builderFactory
                .getBuilder(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(x509Credential);
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            signature.setKeyInfo(keyInfo);
            request.setSignature(signature);
            authnRequestDom = marshallerFactory.getMarshaller(request).marshall(request);
            org.opensaml.xmlsec.signature.support.Signer.signObject(signature);
        } else {
            request.setSignature(null);
            authnRequestDom = marshallerFactory.getMarshaller(request).marshall(request);
        }
        String samlAuthnRequest = SerializeSupport.nodeToString(authnRequestDom);
        samlAuthnRequest = Base64.encode(samlAuthnRequest.getBytes("UTF-8"));
        model.addAttribute("SAMLRequest", samlAuthnRequest);
        return model;
    }

    private String getRedirectAuthnRequestUrl(Boolean isSigned, RequestAbstractType request, String entityId)
        throws MarshallingException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        request.setSignature(null);
        String location = "";
        if (request instanceof AuthnRequest) {
            SingleSignOnService ssoService = metadataService
                    .getMetadata(entityId)
                    .singleSignOnServices
                    .stream()
                    .filter(singleSignOnService -> singleSignOnService.binding.equals(SamlProtocolBinding.HTTP_REDIRECT))
                    .findFirst().orElseThrow(IOException::new);
            request.setDestination(ssoService.location);
            ((AuthnRequest)request).setAssertionConsumerServiceURL(currentHost + "/sso/redirect");
            ((AuthnRequest)request).setProtocolBinding(SamlProtocolBinding.HTTP_REDIRECT.getName());
            location = ssoService.location;
        }
        if (request instanceof LogoutRequest) {
            SingleLogoutService sloService = metadataService
                    .getMetadata(entityId)
                    .singleLogoutServices
                    .stream()
                    .filter(singleLogoutService -> singleLogoutService.binding.equals(SamlProtocolBinding.HTTP_REDIRECT))
                    .findFirst().orElseThrow(IOException::new);
            request.setDestination(sloService.location);
            SessionIndex sessionIndex = ((SessionIndexBuilder) builderFactory.getBuilder(SessionIndex.DEFAULT_ELEMENT_NAME)).buildObject();
            sessionIndex.setSessionIndex(this.sessionIndexes.get(metadataService.getMetadata(entityId).entityId));
            ((LogoutRequest)request).getSessionIndexes().add(sessionIndex);
            location = sloService.location;
        }
        String samlAuthnRequest = createEncodedSamlAuthnRequest(request);

        String query = "SAMLRequest=" + URLEncoder.encode(samlAuthnRequest, "UTF-8");
        if (isSigned) {
            query = query + "&SigAlg=" + URLEncoder.encode(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, "UTF-8");
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(privateKey);
            signature.update(query.getBytes());
            String encodedSignature = Base64.encode(signature.sign());
            query = query + "&Signature=" + URLEncoder.encode(encodedSignature, "UTF-8");
        }
        return location + "?" + query;
    }

    private String createEncodedSamlAuthnRequest(RequestAbstractType request) throws MarshallingException, IOException {
        Marshaller marshaller = marshallerFactory.getMarshaller(request);

        Element authnRequestDom = marshaller.marshall(request);
        String samlAuthnRequest = SerializeSupport.nodeToString(authnRequestDom);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
        deflaterOutputStream.write(samlAuthnRequest.getBytes("UTF-8"));
        deflaterOutputStream.finish();
        return Base64.encode(byteArrayOutputStream.toByteArray());
    }

    private PrivateKey getPrivateKey(String privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException, Base64DecodingException {
        byte[] pkcs8EncodedBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private X509Certificate getX509Certificate() throws Base64DecodingException, CertificateException {
        byte[] decoded;
        decoded = Base64.decode(publicKeyPemCertificate);
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
    }

    private KeyInfo generateKeyInfo(BasicX509Credential x509Credential) {
        X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
        factory.setEmitEntityCertificate(true);
        KeyInfoGenerator generator = factory.newInstance();
        final KeyInfo keyInfo;
        try {
            keyInfo = generator.generate(x509Credential);
            return keyInfo;
        } catch (SecurityException e) {
            e.printStackTrace();
            return null;
        }
    }
}
