package com.imprivata.saml.service;

import com.imprivata.saml.model.IdpSaml2Metadata;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;

public interface MetadataService {
    void setMetadata(MultipartFile file) throws IOException, ComponentInitializationException, ResolverException, ParserConfigurationException, SAXException;
    IdpSaml2Metadata getMetadata() throws IOException;
}
