package utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.util.Scanner;

import abce.xml.bind.JAXBElement;
import abce.xml.bind.JAXBIntrospector;

import abce.xml.bind.JAXB;
import com.ibm.zurich.idmx.exception.SerializationException;
import com.ibm.zurich.idmx.jaxb.JaxbHelperClass;

/**
 *
 */
public class IdemixUtils {

    // Non-instantiable class
    private IdemixUtils() {}

    public static void saveToFile(String object, String filename) throws IOException {

        File file = new File(URI.create(filename));
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }

        OutputStream outputStream;
        outputStream = new FileOutputStream(file);
        OutputStreamWriter out = new OutputStreamWriter(outputStream, "UTF-8");
        out.write(object);
        out.flush();
        out.close();
    }


    @SuppressWarnings("unchecked")
    public static <T> T getResource(String name, Class<T> classOfResource, boolean validate) throws SerializationException {
        String path="/" + name;
        InputStream resource = classOfResource.getResourceAsStream(path);
        JAXBElement<?> resourceAsJaxbElement = JaxbHelperClass.deserialize(resource, validate);
        Object resourceAsObject = JAXBIntrospector.getValue(resourceAsJaxbElement);
        return (T) resourceAsObject;
    }

}
