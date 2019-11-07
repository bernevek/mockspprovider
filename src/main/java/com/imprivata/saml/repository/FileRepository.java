package com.imprivata.saml.repository;

import java.io.IOException;

public interface FileRepository {
    String readSpMetadataFile() throws IOException;
}
