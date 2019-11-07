package com.imprivata.saml.model;

import java.time.Instant;
import java.util.List;

public class IdpSaml2Metadata {

    public String entityId;

    public Instant validUntil;

    public String defaultSamlNameIdFormatEnum;

    public List<String> publicSigningKeyPemCertificates;

    public List<String> publicEncryptionKeyPemCertificates;

    public List<SamlNameIdFormatEnum> samlNameIdFormats;

    public List<SingleSignOnService> singleSignOnServices;

    public List<SingleLogoutService> singleLogoutServices;
}
