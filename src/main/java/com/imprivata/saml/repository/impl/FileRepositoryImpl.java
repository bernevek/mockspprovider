package com.imprivata.saml.repository.impl;

import com.imprivata.saml.repository.FileRepository;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Repository;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@Repository
public class FileRepositoryImpl implements FileRepository {
    @Override
    public String readSpMetadataFile() throws IOException {
        Resource resource = new ClassPathResource("SP.xml");
        InputStream inputStream = resource.getInputStream();
        byte[] bdata = FileCopyUtils.copyToByteArray(inputStream);
        String data = new String(bdata, StandardCharsets.UTF_8);
        return data;
    }
}
