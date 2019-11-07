package com.imprivata.saml.model;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public enum SamlNameIdFormatEnum {

    UNSPECIFIED("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),

    TRANSIENT("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),

    EMAIL_ADDRESS("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),

    WINDOWS_DOMAIN_QUALIFIED_NAME("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"),

    PERSISTENT("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

    private String name;

    private static final Map<String,SamlNameIdFormatEnum> ENUM_MAP;

    SamlNameIdFormatEnum (String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    static {
        Map<String,SamlNameIdFormatEnum> map = new ConcurrentHashMap<String,SamlNameIdFormatEnum>();
        for (SamlNameIdFormatEnum instance : SamlNameIdFormatEnum.values()) {
            map.put(instance.getName(),instance);
        }
        ENUM_MAP = Collections.unmodifiableMap(map);
    }

    public static SamlNameIdFormatEnum get(String name) {
        return ENUM_MAP.get(name);
    }
}
