package com.imprivata.saml.controller;

import com.imprivata.saml.service.SsoSamlService;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.annotation.PostConstruct;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.List;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

@Controller
public class StartController {

    @Autowired
    SsoSamlService ssoSamlService;

    private DocumentBuilderFactory documentBuilderFactory;
    private DocumentBuilder builder;

    @PostConstruct
    public void init() {
        documentBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            builder = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
    }

    @PostMapping(value = {"/sso/redirect", "/sso/post"})
    public String sso(Model model, @RequestBody MultiValueMap<String, String> formData) {
        String response;
        try {
            response = new String(Base64.decode(formData.get("SAMLResponse").get(0)));
            Document responseDoc = builder.parse(new InputSource(new StringReader(response)));
            String sessionIndex = responseDoc.getElementsByTagName("saml2:AuthnStatement").item(0).getAttributes().getNamedItem("SessionIndex").getNodeValue();
            String entityId = responseDoc.getElementsByTagName("saml2:Issuer").item(0).getNodeValue();
//            ssoSamlService.setSessionIndex(sessionIndex);
            ssoSamlService.addSessionIndex(entityId, sessionIndex);
            response = SerializeSupport.prettyPrintXML(responseDoc);
        } catch (Base64DecodingException | IOException | SAXException e) {
            e.printStackTrace();
            return "/badRequest";
        }
        model.addAttribute("SAMLResponse", response);
        return "/response";
    }

    @PostMapping(value = "/slo/post")
    public String sloPost(Model model, @RequestBody MultiValueMap<String, String> formData) {
        String response;
        try {
            response = new String(Base64.decode(formData.get("SAMLResponse").get(0)));
            Document responseDoc = builder.parse(new InputSource(new StringReader(response)));
            response = SerializeSupport.prettyPrintXML(responseDoc);
        } catch (Base64DecodingException | SAXException | IOException e) {
            e.printStackTrace();
            return "/badRequest";
        }
        model.addAttribute("SAMLResponse", response);
        return "/response";
    }

    @GetMapping(value = "/slo/redirect")
    public String sloRedirect(Model model, @RequestParam String SAMLResponse, @RequestParam String SigAlg, @RequestParam String Signature) {
        String response;
        try {
            Inflater inflater = new Inflater(true);
            inflater.setInput(Base64.decode(SAMLResponse));
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(byteArrayOutputStream, inflater);
            inflaterOutputStream.flush();
            response = new String(byteArrayOutputStream.toByteArray());
            Document responseDoc = builder.parse(new InputSource(new StringReader(response)));
            response = SerializeSupport.prettyPrintXML(responseDoc);
        } catch (Base64DecodingException | SAXException | IOException e) {
            e.printStackTrace();
            return "/badRequest";
        }
        model.addAttribute("SAMLResponse", response);
        model.addAttribute("SigAlg", SigAlg);
        model.addAttribute("Signature", Signature);
        return "/response";
    }
}
