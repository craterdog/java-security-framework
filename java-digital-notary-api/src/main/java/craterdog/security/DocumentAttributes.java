/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
package craterdog.security;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import craterdog.primitives.Tag;
import craterdog.smart.SmartObject;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This class defines the attributes that make up a document that can be notarized.
 *
 * @author Derk Norton
 */
public class DocumentAttributes extends SmartObject<DocumentAttributes> {

    /**
     * A watermark describing how the document is signed and when it expires.
     */
    public Watermark watermark;


    /*
     * This map is used to hold all document attributes and are automatically mapped to JSON.
     */
    private final Map<String, Object> attributes = new LinkedHashMap<>();


    /**
     * This method returns the value of the attribute associated with the specified
     * name, or null if none exists.
     *
     * @param name The name of the attribute to be returned.
     * @return The value of the attribute.
     */
    public Object get(String name) {
        return attributes.get(name);
    }


    /**
     * This method allows the setting of attributes that are not explicitly defined.
     *
     * @param name The name of the attribute.
     * @param value The value to be associated with this attribute name.
     * @return Any previous attribute value associated with this attribute name.
     */
    @JsonAnySetter
    public Object put(String name, Object value) {
        return attributes.put(name, value);
    }


    /**
     * This method returns a map of the attributes that are not explicitly defined.  It
     * is primarily used by the Jackson parser during deserialization of the corresponding JSON.
     *
     * @return A map containing the attributes.
     */
    @JsonAnyGetter
    public Map<String, Object> any() {
        return attributes;
    }


    /**
     * The default constructor ensures that the custom attribute types (like tags) will be
     * formatted correctly when printed.
     */
    public DocumentAttributes() {
        this.addSerializableClass(Tag.class);
    }

}
