package com.imprivata.saml.controller;

import com.imprivata.saml.repository.FileRepository;
import com.imprivata.saml.service.MetadataService;
import com.imprivata.saml.service.SsoSamlService;
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

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

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

    @PostConstruct
    public void init() {
        currentHost = domain + ":" + port;
    }

    @GetMapping(value = "/postBinding")
    public String postAuthRequest(Model model, @RequestParam(required = false) boolean isSigned, @RequestParam(required = false) String entityId) {
        try {
            if (isSigned) {
                ssoSamlService.createSignedPostAuthnRequest(model, entityId);
            }
            else
                ssoSamlService.createPostAuthnRequest(model, entityId);
        } catch (MarshallingException |
                IOException |
                org.opensaml.xmlsec.signature.support.SignatureException e) {
            return "badRequest";
        }
        return "postBinding";
    }

    @GetMapping(value = "/redirectBinding")
    public String redirectAuthRequest(@RequestParam(required = false) boolean isSigned, @RequestParam(required = false) String entityId) {
        try {
            if (isSigned)
                return "redirect:" + ssoSamlService.createSignedRedirectAuthnRequest(entityId);
            else
                return "redirect:" + ssoSamlService.createRedirectAuthnRequest(entityId);
        } catch (InvalidKeyException |
                SignatureException |
                NoSuchAlgorithmException |
                MarshallingException |
                IOException e) {
            return "badRequest";
        }
    }

    @GetMapping(value = "/sloPostBinding")
    public String postLogoutRequest(Model model, @RequestParam(required = false) boolean isSigned, @RequestParam(required = false) String entityId) {
        try {
            if (isSigned) {
                ssoSamlService.createSignedPostLogoutRequest(model, entityId);
            }
            else
                ssoSamlService.createPostLogoutRequest(model, entityId);
        } catch (MarshallingException |
                IOException |
                org.opensaml.xmlsec.signature.support.SignatureException e) {
            return "badRequest";
        }
        return "postBinding";
    }

    @GetMapping(value = "/SpMetadata")
    public ResponseEntity<?> getSpMetadata() throws IOException {
        String metadata = fileRepository.readSpMetadataFile().replaceAll("http://localhost:9090", currentHost);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.TEXT_XML);
        return new ResponseEntity<>(metadata.getBytes(), responseHeaders, HttpStatus.OK);
    }
}
