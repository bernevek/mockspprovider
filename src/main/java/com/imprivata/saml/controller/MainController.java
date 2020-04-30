package com.imprivata.saml.controller;

import com.imprivata.saml.repository.FileRepository;
import com.imprivata.saml.service.MetadataService;
import com.imprivata.saml.service.SsoSamlService;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static com.imprivata.saml.common.Constants.DELETED;
import static com.imprivata.saml.common.Constants.SESSION_COOKIE;

@Controller()
public class MainController {
    @Autowired
    MetadataService metadataService;
    @Autowired
    SsoSamlService ssoSamlService;
    @Autowired
    FileRepository fileRepository;


    @Value("${domain}")
    private String domain;

    @Value("${server.port}")
    private String port;

    @Value("${encriptedPrivateKey}")
    public String encriptedPrivateKey;

    @Value("${publicKeyPemCertificate}")
    public String publicKeyPemCertificate;

    private String currentHost;

    private DocumentBuilderFactory documentBuilderFactory;

    private DocumentBuilder builder;

    @PostConstruct
    public void init() {
        currentHost = domain + ":" + port;
        documentBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            builder = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
    }

    @GetMapping(value = "/postBinding")
    public String postAuthRequest(
        Model model,
        @CookieValue(name = SESSION_COOKIE, defaultValue = DELETED) String sessionCookie,
        @RequestParam(required = false) boolean isSigned,
        @RequestParam(required = false) String entityId,
        @RequestParam(required = false) String requestId
    ) {
        if (!sessionCookie.equals(DELETED)) {
            return "spSession";
        }
        try {
            if (isSigned) {
                ssoSamlService.createSignedPostAuthnRequest(model, entityId, requestId);
            }
            else
                ssoSamlService.createPostAuthnRequest(model, entityId, requestId);
        } catch (MarshallingException |
                IOException |
                org.opensaml.xmlsec.signature.support.SignatureException e) {
            return "badRequest";
        }
        return "postBinding";
    }

    @GetMapping(value = "/redirectBinding")
    public String redirectAuthRequest(
        @CookieValue(name = SESSION_COOKIE, defaultValue = DELETED) String sessionCookie,
        @RequestParam(required = false) boolean isSigned,
        @RequestParam(required = false) String entityId,
        @RequestParam(required = false) String requestId
    ) {
        if (!sessionCookie.equals(DELETED)) {
            return "spSession";
        }
        try {
            if (isSigned)
                return "redirect:" + ssoSamlService.createSignedRedirectAuthnRequest(entityId, requestId);
            else
                return "redirect:" + ssoSamlService.createRedirectAuthnRequest(entityId, requestId);
        } catch (InvalidKeyException |
                SignatureException |
                NoSuchAlgorithmException |
                MarshallingException |
                IOException e) {
            return "badRequest";
        }
    }

    @GetMapping(value = "/sloPostBinding")
    public String postLogoutRequest(
        Model model,
        @RequestParam(required = false) boolean isSigned,
        @RequestParam(required = false) String entityId,
        @RequestParam(required = false) String requestId
    ) {
        try {
            if (isSigned) {
                ssoSamlService.createSignedPostLogoutRequest(model, entityId, requestId);
            }
            else
                ssoSamlService.createPostLogoutRequest(model, entityId, requestId);
        } catch (MarshallingException |
                IOException |
                org.opensaml.xmlsec.signature.support.SignatureException e) {
            return "badRequest";
        }
        return "postBinding";
    }

    @GetMapping(value = "/sloRedirectBinding")
    public String redirectLogoutRequest(
        @RequestParam(required = false) boolean isSigned,
        @RequestParam(required = false) String entityId,
        @RequestParam(required = false) String requestId
    ) {
        try {
            if (isSigned) {
                return "redirect:" + ssoSamlService.createSignedRedirectLogoutRequest(entityId, requestId);
            }
            else
                return "redirect:" + ssoSamlService.createRedirectLogoutRequest(entityId, requestId);
        } catch (MarshallingException |
                IOException |
                NoSuchAlgorithmException |
                SignatureException |
                InvalidKeyException e) {
            return "badRequest";
        }
    }

    @GetMapping(value = "/terminateSpSession")
    public String terminateSpSession(Model model, @CookieValue(name = SESSION_COOKIE, defaultValue = DELETED) String sessionCookieValue, HttpServletResponse servletResponse) {
        if (!sessionCookieValue.equals(DELETED)) {
            Cookie sessionCookie = new Cookie(SESSION_COOKIE, DELETED);
            sessionCookie.setPath("/");
            servletResponse.addCookie(sessionCookie);
        }
        model.addAttribute("SpSession", DELETED);
        return "spSession";
    }

    @GetMapping(value = "/SpMetadata")
    public ResponseEntity<?> getSpMetadata(@RequestParam(required = false) boolean redirectBinding) throws IOException, SAXException {
        String metadata = fileRepository.readSpMetadataFile().replaceAll("http://localhost:9090", currentHost);
        Document metadataDoc = builder.parse(new InputSource(new StringReader(metadata)));
        Node spSsoDescriptor = metadataDoc.getElementsByTagName("md:SPSSODescriptor").item(0);
        Element sloPostBinding = metadataDoc.createElement("md:SingleLogoutService");
        sloPostBinding.setAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        sloPostBinding.setAttribute("Location", currentHost + "/slo/post");
        Element sloRedirectBinding = metadataDoc.createElement("md:SingleLogoutService");
        sloRedirectBinding.setAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        sloRedirectBinding.setAttribute("Location", currentHost + "/slo/redirect");
        if (redirectBinding) {
            spSsoDescriptor.appendChild(sloRedirectBinding);
            spSsoDescriptor.appendChild(sloPostBinding);
        } else {
            spSsoDescriptor.appendChild(sloPostBinding);
            spSsoDescriptor.appendChild(sloRedirectBinding);
        }
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.TEXT_XML);
        return new ResponseEntity<>(SerializeSupport.nodeToString(metadataDoc).getBytes(), responseHeaders, HttpStatus.OK);
    }
}
