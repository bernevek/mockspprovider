package com.imprivata.saml.model;

public class SingleLogoutService {

    public SingleLogoutService(String location, SamlProtocolBinding binding) {
        this.location = location;
        this.binding = binding;
    }

    public String location;

    public SamlProtocolBinding binding;
}
