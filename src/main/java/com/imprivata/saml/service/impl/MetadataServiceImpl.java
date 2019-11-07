package com.imprivata.saml.service.impl;

import com.imprivata.saml.model.*;
import com.imprivata.saml.service.MetadataService;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.credential.UsageType;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class MetadataServiceImpl implements MetadataService {

    private IdpSaml2Metadata metadata;

    @Override
    public void setMetadata(MultipartFile file) throws IOException, ComponentInitializationException, ResolverException, ParserConfigurationException, SAXException {
        EntityDescriptor entityDescriptor = readFromFile(file);
        metadata = getIdpSaml2Metadata(entityDescriptor);
    }

    @Override
    public IdpSaml2Metadata getMetadata() throws IOException {
        if (metadata == null)
            throw new IOException("No Idp metadata");
        return this.metadata;
    }

    private EntityDescriptor readFromFile(MultipartFile uploadedInput) throws IOException, ComponentInitializationException, ResolverException, ParserConfigurationException, SAXException {

        InputStream targetStream = uploadedInput.getInputStream();

        Document metadataDoc = getDocument(targetStream);
        if (metadataDoc == null) {
            return null;
        }
        return resolveSpMetadataDoc(metadataDoc);
    }

    private EntityDescriptor resolveSpMetadataDoc(Document metadataDoc) throws ComponentInitializationException, ResolverException {

        Element metadataDocElement = metadataDoc.getDocumentElement();
        DOMMetadataResolver metadataResolver =
                new DOMMetadataResolver(metadataDocElement);
        String entityId = metadataDocElement.getAttribute("entityID");
        metadataResolver.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
        metadataResolver.setFailFastInitialization(true);
        metadataResolver.setRequireValidMetadata(true);
        metadataResolver.setId(metadataResolver.getClass().getCanonicalName());
        metadataResolver.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
        metadataResolver.initialize();
        CriteriaSet crit = new CriteriaSet(new EntityIdCriterion(entityId));
        EntityDescriptor entityDescriptor = metadataResolver.resolveSingle(crit);

        return entityDescriptor;
    }

    private Document getDocument(InputStream inputStream) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(inputStream);
        return doc;
    }

    private IdpSaml2Metadata getIdpSaml2Metadata(EntityDescriptor entityDescriptor) {
        if ((entityDescriptor != null) && entityDescriptor.isValid()) {
            return getRequiredIdpMetadata(entityDescriptor);
        } else {
            return null;
        }
    }

    private IdpSaml2Metadata getRequiredIdpMetadata(EntityDescriptor entityDescriptor) {
        if ((entityDescriptor != null)
                && entityDescriptor.getRoleDescriptors().iterator().hasNext()) {
            IDPSSODescriptor roleDescriptor = (IDPSSODescriptor) entityDescriptor
                    .getRoleDescriptors().iterator().next();
            IdpSaml2Metadata idpSaml2Metadata = new IdpSaml2Metadata();
            idpSaml2Metadata.entityId = entityDescriptor.getEntityID();
            idpSaml2Metadata.singleSignOnServices = mapSingleSignOnServices(roleDescriptor);
            idpSaml2Metadata.samlNameIdFormats = mapSamlNameIdFormats(roleDescriptor);

            idpSaml2Metadata.defaultSamlNameIdFormatEnum = idpSaml2Metadata.samlNameIdFormats.isEmpty() ?
                    SamlNameIdFormatEnum.values()[0].name()
                    : idpSaml2Metadata.samlNameIdFormats.get(0).name();

            if(roleDescriptor.getSingleLogoutServices() != null) {
                idpSaml2Metadata.singleLogoutServices = mapSingleLogoutServices(roleDescriptor);
            }

            if(entityDescriptor.getValidUntil() != null){
                idpSaml2Metadata.validUntil =
                        Instant.ofEpochMilli(entityDescriptor.getValidUntil().getMillis());
            }

            idpSaml2Metadata.publicEncryptionKeyPemCertificates = getPemCertificatesByUsageType(roleDescriptor, UsageType.ENCRYPTION);

            idpSaml2Metadata.publicSigningKeyPemCertificates = getPemCertificatesByUsageType(roleDescriptor, UsageType.SIGNING);

            return idpSaml2Metadata;
        }
        return null;
    }

    private List<SamlNameIdFormatEnum> mapSamlNameIdFormats(IDPSSODescriptor roleDescriptor) {
        return roleDescriptor.getNameIDFormats().stream()
                .filter(p -> SamlNameIdFormatEnum.get(p.getFormat()) != null)
                .map(p -> SamlNameIdFormatEnum.get(p.getFormat()))
                .sorted(Comparator.comparing(p -> p))
                .collect(Collectors.toList());
    }

    private List<SingleSignOnService> mapSingleSignOnServices(
            IDPSSODescriptor roleDescriptor) {
        return roleDescriptor.getSingleSignOnServices().stream()
                .filter(p -> SamlProtocolBinding.get(p.getBinding()) != null)
                .map(p -> new SingleSignOnService(p.getLocation(),
                        SamlProtocolBinding.get(p.getBinding())))
                .collect(Collectors.toList());
    }

    private List<SingleLogoutService> mapSingleLogoutServices(IDPSSODescriptor roleDescriptor) {
        return roleDescriptor.getSingleLogoutServices().stream()
                .filter(p -> SamlProtocolBinding.get(p.getBinding()) != null)
                .map(p -> new SingleLogoutService(p.getLocation(),
                        SamlProtocolBinding.get(p.getBinding())))
                .collect(Collectors.toList());
    }

    private List<String> getPemCertificatesByUsageType(IDPSSODescriptor roleDescriptor,
                                                       UsageType usageType) {
        return roleDescriptor.getKeyDescriptors().stream()
                        .filter(keyDescriptor -> keyDescriptor.getUse() == usageType)
                        .map(keyDescriptor -> keyDescriptor.getKeyInfo().getX509Datas())
                        .flatMap(List::stream)
                        .map(x509Data -> x509Data.getX509Certificates())
                        .flatMap(List::stream)
                        .map(x509Certificate -> x509Certificate.getValue().replaceAll("\n", ""))
                        .collect(Collectors.toList());
    }
}
