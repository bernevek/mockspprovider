package com.imprivata.saml.controller;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.annotation.PostConstruct;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.util.List;
import java.util.Map;

@Controller
public class StartController {


    DocumentBuilderFactory documentBuilderFactory;
    DocumentBuilder builder;

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
    public ResponseEntity<?> redirect(@RequestBody MultiValueMap<String, String> formData) {
        String response = null;
        try {
            response = new String(Base64.decode(formData.get("SAMLResponse").get(0)));
            Document doc = builder.parse(new InputSource(new StringReader(response)));
//            System.out.println(doc.getElementsByTagName("saml2:AuthnStatement").item(0).getAttributes().getNamedItem("SessionIndex").getNodeValue());
        } catch (Base64DecodingException | IOException | SAXException e) {
            e.printStackTrace();
        }
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.TEXT_XML);
        return new ResponseEntity<>(response, responseHeaders, HttpStatus.OK);
    }
}
