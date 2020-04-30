package com.imprivata.saml.controller;

import com.imprivata.saml.service.SsoSamlService;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import static com.imprivata.saml.common.Constants.DELETED;
import static com.imprivata.saml.common.Constants.SESSION_COOKIE;

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
    public String sso(Model model, @RequestBody MultiValueMap<String, String> formData, HttpServletResponse servletResponse) {
        String response;
        try {
            response = new String(Base64.decode(formData.get("SAMLResponse").get(0)));
            Document responseDoc = builder.parse(new InputSource(new StringReader(response)));
            String sessionIndex = responseDoc.getElementsByTagName("saml2:AuthnStatement").item(0).getAttributes().getNamedItem("SessionIndex").getNodeValue();
            String entityId = responseDoc.getElementsByTagName("saml2:Issuer").item(0).getNodeValue();
            ssoSamlService.addSessionIndex(entityId, sessionIndex);
            response = SerializeSupport.prettyPrintXML(responseDoc);
            model.addAttribute("SAMLResponse", response);
            servletResponse = setSessionCookie(sessionIndex, servletResponse);
            return "/response";
        } catch (Base64DecodingException | IOException | SAXException e) {
            e.printStackTrace();
            servletResponse = setSessionCookie(DELETED, servletResponse);
            return "/badRequest";
        }
    }

    @PostMapping(value = "/slo/post")
    public String sloPost(Model model, @RequestBody MultiValueMap<String, String> formData, HttpServletResponse servletResponse) {
        String response;
        servletResponse = setSessionCookie(DELETED, servletResponse);
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
    public String sloRedirect(Model model, @RequestParam String SAMLResponse, @RequestParam String SigAlg, @RequestParam String Signature, HttpServletResponse servletResponse) {
        String response;
        servletResponse = setSessionCookie(DELETED, servletResponse);
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

    private HttpServletResponse setSessionCookie(String cookie, HttpServletResponse servletResponse) {
        Cookie sessionCookie = new Cookie(SESSION_COOKIE, cookie);
        sessionCookie.setPath("/");
        servletResponse.addCookie(sessionCookie);
        return servletResponse;
    }
}
