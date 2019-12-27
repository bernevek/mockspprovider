package com.imprivata.saml.controller;

import com.imprivata.saml.service.MetadataService;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;

@Controller
public class MetadataController {

    @Autowired
    private MetadataService metadataService;

    @RequestMapping(value="/uploadMetadata", method= RequestMethod.POST )
    public ResponseEntity<?> uploadMetadata(@RequestParam("metadata") MultipartFile file){
        String fileName = null;
        if (!file.isEmpty()) {
            try {
                fileName = file.getOriginalFilename();
                metadataService.setMetadata(file);

                return new ResponseEntity<>("You have successfully uploaded " + fileName, HttpStatus.OK);
            } catch (Exception e) {
                return new ResponseEntity<>("You failed to upload " + fileName + ": " + e.getMessage(), HttpStatus.BAD_REQUEST);
            }
        } else {
            return new ResponseEntity<>("Unable to upload. File is empty.", HttpStatus.BAD_REQUEST);
        }
    }

    @RequestMapping(value="/uploadMetadata", method= RequestMethod.GET )
    public ResponseEntity<?> addMetadataFromUrl(@RequestParam("url") String url){
        try {
            metadataService.setMetadata(url);
            return new ResponseEntity<>("You have successfully uploaded metadata", HttpStatus.OK);
        } catch (IOException |
                ParserConfigurationException |
                SAXException |
                ResolverException |
                ComponentInitializationException e) {
            return new ResponseEntity<>("You failed to upload metadata : " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @RequestMapping(value="/deleteMetadata", method= RequestMethod.GET )
    public ResponseEntity<?> deleteMetadata(@RequestParam("entityId") String entityId){
        metadataService.deleteMetadata(entityId);
        return new ResponseEntity<>("You have successfully deleted metadata", HttpStatus.OK);
    }

    @RequestMapping(value="/metadatas", method= RequestMethod.GET )
    public ResponseEntity<?> getMetadatas(){
        return new ResponseEntity<>(metadataService.getMetadatas(), HttpStatus.OK);
    }
}
