package com.imprivata.saml.controller;

import com.imprivata.saml.service.MetadataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class MetadataController {

    @Autowired
    private MetadataService metadataService;

    @RequestMapping(value="/uploadMetadata", method= RequestMethod.POST )
    public ResponseEntity<?> singleSave(@RequestParam("metadata") MultipartFile file){
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
}
