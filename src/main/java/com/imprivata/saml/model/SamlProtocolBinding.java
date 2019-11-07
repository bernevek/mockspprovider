package com.imprivata.saml.model;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public enum SamlProtocolBinding {
    HTTP_REDIRECT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),

    HTTP_POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),

    HTTP_ARTIFACT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"),

    SOAP("urn:oasis:names:tc:SAML:2.0:bindings:SOAP");

    private String name;

    private static final Map<String,SamlProtocolBinding> ENUM_MAP;

    SamlProtocolBinding (String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    // Build an immutable map of String name to enum pairs.

    static {
        Map<String,SamlProtocolBinding> map = new ConcurrentHashMap<String,SamlProtocolBinding>();
        for (SamlProtocolBinding instance : SamlProtocolBinding.values()) {
            map.put(instance.getName(),instance);
        }
        ENUM_MAP = Collections.unmodifiableMap(map);
    }

    public static SamlProtocolBinding get(String name) {
        return ENUM_MAP.get(name);
    }
}
