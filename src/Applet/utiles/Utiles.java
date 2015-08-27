/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Applet.utiles;

import java.awt.Color;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import javax.swing.JButton;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author JMiraballes
 * 
 * Clase contiene metodos estaticos utilitarios, que puden ser
 * accedidos de forma sencilla desde cualquier punto.
 * 
 */
public class Utiles {

    public static final String PATH_WIN = "APPDATA";
    public static final String PATH_UNIX = "user.home";
    
    public static final String PATH_IGDOC_WIN = "/IGDoc";
    public static final String PATH_IGDOC_UNIX = "/.IGDoc";
    
    public static final String PATH_ALMACEN = "/almacenIGDOC";
    public static final String PATH_PRIVATE_KEYS = "/privateKeys";
    
    public static String TIPO_KEYSTORE_JKS = "jks";
    public static String TIPO_KEYSTORE_PKCS12 = "PKCS12";
    
    public static String MENSAJE_ERROR = "No se puede descargar el certificado.";
    
    public static final SimpleDateFormat DATE_FORMAT_MIN = new SimpleDateFormat("dd/MM/yyyy");
    
    /**
     * Se agrega el proveedor de seguridad.
     */
    public static void addProvider(){
        Security.addProvider(new BouncyCastleProvider());
    }
    
    public static boolean isNullOrEmpty(String value){
        return (value == null || value.isEmpty() || value.equals("null"));
    }    
    
    /*
     Convierte un pkcs10 en un Base64.
     * @param pkcs10 
     * @return baseString 
     */
    public static String convertPKCS10ToBase64( PKCS10CertificationRequest pkcs10 ){
        byte[] pk = Base64.encode(pkcs10.getEncoded());
        String baseString="";
        for (int i=0; i < pk.length;i++){
            baseString = baseString+(char)pk[i];
        } 
        return baseString;
    }
    
    /*
     Convierte un Certificado en base64 y
    retorna un String
    */
    public static String convertX509ToBase64(X509Certificate cert) throws CertificateEncodingException {
        
        byte[] pk = Base64.encode(cert.getEncoded());
        String certString ="";
        for (int i=0;i < pk.length;i++){
            certString=certString+(char)pk[i];
        }  
        return certString;
    }
    
    /**
    Método que a partir de un certificado en Base 64, devuelve una instancia de 
    * la clase X509Certificate.
    * @return X509Certificate
    * @param certBase64
    * @throws CertificateException
     */
    public static X509Certificate decodeCertificate( String certBase64 ) throws CertificateException{
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream isCertCA = new ByteArrayInputStream(Base64.decode(certBase64));
        X509Certificate caCert = (X509Certificate)cf.generateCertificate(isCertCA);
        return caCert;        
    }
    
    /*
    Obtiene el path del keystore
    */
    public static String obtenerKeystorePath(){
        String path;
        if (isOSWindows()){
            path = System.getenv( PATH_WIN ) + PATH_IGDOC_WIN;
            path = path.replace("\\", "/");
        }else{
            path = System.getProperty( PATH_UNIX)+ PATH_IGDOC_UNIX;
            path = path.replace("\\", "/");
        }
        return path;
    }
    
    /*
    Función que me indica si estoy en Windwos
    */
    public static boolean isOSWindows() {
        return (System.getProperty("os.name").toLowerCase().startsWith("win"));
    }
    
    
    /*Guarda keystore pasador por parámetro en /privateKeys*/
    public static void guardarKeyStore(KeyStore ks) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
        String path = Utiles.obtenerKeystorePath();
        File myDir = new File(path);
        if( !myDir.exists() ){
            myDir.mkdir();
        }
        FileOutputStream out = new FileOutputStream(path + PATH_PRIVATE_KEYS);
        ks.store(out, "default".toCharArray());
        out.close();
    }

    /*Obtiene el keystore desde /privateKeys*/
    public static KeyStore obtenerKeyStore() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException{
        String path = Utiles.obtenerKeystorePath() + PATH_PRIVATE_KEYS;
        KeyStore aRet = KeyStore.getInstance("jks");
        File myDir = new File(path);
        if( myDir.exists() ){
            FileInputStream in= new FileInputStream(path);
            aRet.load(in, "default".toCharArray());
            in.close();
        }else{
            aRet.load(null,null);
        }
        return aRet;
    }
    
    /* Obtiene el keystore desde /almacenIGDOC */
    public static KeyStore obtenerKeyStoreDesdeAlmacen() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException{
        String path = Utiles.obtenerKeystorePath() + PATH_ALMACEN;
        KeyStore aRet = KeyStore.getInstance("jks");
        File myDir = new File(path);
        if( myDir.exists() ){
            FileInputStream in= new FileInputStream(path);
            aRet.load(in, "default".toCharArray());
            in.close();
        }else{
            aRet.load(null,null);
        }
        return aRet;
    }
    
    /** Guarda el keystore pasado por parámetro en /almacenIGDOC
     * @param ks
     * @throws java.security.KeyStoreException
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.cert.CertificateException */
    public static void guardarKeyStoreEnAlmacen(KeyStore ks) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
        String path = Utiles.obtenerKeystorePath();
        File myDir = new File(path);
        if( !myDir.exists() ){
            myDir.mkdir();
        }
        FileOutputStream out = new FileOutputStream(path + PATH_ALMACEN);
        ks.store(out, "default".toCharArray());
        out.close();
    }            
       
    /**
     * Función para obtener el nombre identificado por CN= 
     * @return String
     * @param nombre
     */
    public static String getCN(String nombre){
        String[] arreglo;
        arreglo = nombre.split(",");
        for (int i = 0; i < arreglo.length; i++){
            if(arreglo[i].startsWith(" CN=")||arreglo[i].startsWith("CN=")){
                if(arreglo[i].startsWith(" CN="))
                    return arreglo[i].replace(" CN=", "");
                else
                    return arreglo[i].replace("CN=", "");
            }
        }
        return "";
    }
    
    /**
     * Método que retorna un nombre distintivo de un usuario
     * en trustex, a partir de los valores pasados por parámetro.
     * El parámetro cn es obligatorio, pero o y oU son parámetros
     * opcionales.
     * 
     * @param cn
     * @param oU
     * @return 
     */
    public static String getDN (String cn, String oU){   
        String dn = "CN=" + cn;
        
        if (!isNullOrEmpty(oU)){
            dn += ",OU="+oU;
        }

        return dn;
    }
    
    /** 
        Obtiene el keystore pkcs12 del archivo pasado por parámetro
        utilizando el password también pasado por parámetro.
        @return KeyStore
        @param file
        @param password
     * @throws java.io.FileNotFoundException
     * @throws java.security.KeyStoreException
     * @throws java.security.NoSuchAlgorithmException
    */
    public static KeyStore obtenerKeyStoreDesdeArchivo( File file, char[] password) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
        FileInputStream fi = new FileInputStream(file);
        //Carga el keystorePKCS12 del password dado en el front y el certificado cargado.
        KeyStore ksP12 = KeyStore.getInstance("PKCS12");
        //Loads this KeyStore from the given input stream
        ksP12.load(fi, password);
        
        return ksP12;
    }
    
    /**
     * Obtener obtiene keystore. Se le pasa el path, password y el 
     * tipo de keystore.
     * @param path
     * @param tipo
     * @param password
     * @return 
     * @throws java.io.FileNotFoundException 
     * @throws java.security.KeyStoreException 
     * @throws java.security.NoSuchAlgorithmException 
     * @throws java.security.cert.CertificateException 
     */
    public static KeyStore getKeyStore(String path, String tipo, char[] password) throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException{
        FileInputStream fi = new FileInputStream(path);
        KeyStore ks = KeyStore.getInstance(tipo);
        ks.load(fi, password);
        
        return ks;
    }
    
    /**
     * Método que devuelve un archivo en base 64. Se pasa por parámetro la
     * ruta del archivo.
     * @param fileName
     * @return 
     * @throws java.io.IOException
     */
    public static String encodeFileToBase64Binary(String fileName) throws IOException {
        String encodedString = "";
        if (!isNullOrEmpty(fileName)) {
            File file = new File(fileName);
            byte[] bytes = loadFile(file);
            byte[] encoded = Base64.encode(bytes); 
            encodedString = new String(encoded);
        }
        return encodedString;
    }

    /**
     * Retorna un array de bites a partir de un archivo.
     * 
     * @param file
     * @return 
     * @throws java.io.IOException
     */
    public static byte[] loadFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);

        long length = file.length();
        if (length > Integer.MAX_VALUE) {
            // File is too large
        }
        byte[] bytes = new byte[(int) length];

        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
                && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + file.getName());
        }

        is.close();
        return bytes;
    } 
    
    /**
     * Método encargado de retornar la huella digital del certificado
     * pasado por parámetro. Esta propiedad del certificado, es utilizada
     * para insertar un certificado en trustedX.
     * @param cert
     * @return 
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.cert.CertificateEncodingException
     */
    public static String getThumbPrint(X509Certificate cert) 
    	throws NoSuchAlgorithmException, CertificateEncodingException {
    	MessageDigest md = MessageDigest.getInstance("SHA-1");
    	byte[] der = cert.getEncoded();
    	md.update(der);
    	byte[] digest = md.digest();
    	return hexify(digest);

    }

    public static String hexify (byte bytes[]) {

    	char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', 
    			'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    	StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
        	buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }
        return buf.toString();
    }
    
    public static String convertToSHA256( String str ) throws NoSuchAlgorithmException{
        MessageDigest sha = MessageDigest.getInstance("SHA1");
        sha.digest(str.getBytes());
        return org.apache.axis.encoding.Base64.encode(sha.digest(str.getBytes()));
    } 
    
    public static boolean validarPassword( String password, StringBuilder mensajeError ){
        boolean validado = true;
        if (password.length() <= 7){
            validado = false;
            mensajeError.append("La contraseña debe tener 8 o más caracteres.");
        }    
        else if (!password.matches(".*[0-9].*") || !password.matches(".*[A-za-z].*")){
            validado = false;
            mensajeError.append("La contraseña debe tener letras y números.");
        }
        else if (password.length() > 50){
            validado = false;
            mensajeError.append("La contraseña no debe tener más de 50 caracteres.");
        }   
        return validado;
    } 
    
    public static double convertTimeMillisToSeconds(long millisSecond){
        return millisSecond / 1000.0;
    }
    
    public static Color getInitColorButton(){
        Color color = new Color (57, 155, 255);
        return color;
    }
    
    public static Color getColorHoverButton(){
        Color color = new Color(49, 134, 220);
        return color;
    }
}
